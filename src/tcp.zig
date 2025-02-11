const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const IPv4 = @import("ipv4.zig");
const Connection = @import("conn.zig");
const ConnKey = Connection.Id;

const Self = @This();

const vtable = IPv4.Handler.VTable{ .handle = vhandle };

const RsvFlags = switch (native_endian) {
    .big => packed struct {
        doff: u4,
        rsv: u4,
        cwr: bool,
        ece: bool,
        urg: bool,
        ack: bool,
        psh: bool,
        rst: bool,
        syn: bool,
        fin: bool,
    },
    .little => packed struct {
        rsv: u4,
        doff: u4,
        fin: bool,
        syn: bool,
        rst: bool,
        psh: bool,
        ack: bool,
        urg: bool,
        ece: bool,
        cwr: bool,
    },
};

pub fn tcpChecksum(saddr: u32, daddr: u32, proto: u8, data: []const u8) u16 {
    var csum: u32 = 0;
    csum += saddr;
    csum += daddr;
    csum += std.mem.nativeToBig(u16, proto);
    csum += std.mem.nativeToBig(u16, @truncate(data.len));

    const end = data.len - data.len % 2;
    for (std.mem.bytesAsSlice(u16, data[0..end])) |w| {
        csum += w;
    }

    if (end != data.len) {
        csum += data[end];
    }

    while (csum >> 16 != 0) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return @truncate(~csum);
}

pub const Header = extern struct {
    sport: u16 align(1),
    dport: u16 align(1),
    seq: u32 align(1),
    ack: u32 align(1),
    rsv_flags: RsvFlags align(1), // data offset, reserved bits and flags
    window: u16 align(1),
    csum: u16 align(1),
    urgent: u16 align(1),
    // TODO: handle TCP options

    pub fn fromBytes(bytes: []const u8) Header {
        return std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
    }

    pub fn checksum(
        self: Header,
        saddr: u32,
        daddr: u32,
        proto: u8,
        data: []const u8,
    ) u16 {
        var csum: u32 = 0;
        csum += saddr;
        csum += daddr;
        csum += std.mem.nativeToBig(u16, proto);
        csum += std.mem.nativeToBig(
            u16,
            @truncate(@sizeOf(Header) + data.len),
        );

        const bytes = std.mem.asBytes(&self);
        for (std.mem.bytesAsSlice(u16, bytes)) |w| {
            csum += w;
        }

        const end = data.len - data.len % 2;
        for (std.mem.bytesAsSlice(u16, data[0..end])) |w| {
            csum += w;
        }

        if (end != data.len) {
            csum += data[end];
        }

        while (csum >> 16 != 0) {
            csum = (csum & 0xffff) + (csum >> 16);
        }

        return @truncate(~csum);
    }

    pub fn dataOffset(self: Header) usize {
        return @as(usize, self.rsv_flags.doff) * 4;
    }
};

pub const Segment = struct {
    header: Header,
    // options: ?[]Options,
    data: []const u8,

    pub fn fromPacket(packet: *const IPv4.Packet) !Segment {
        if (tcpChecksum(
            packet.header.saddr,
            packet.header.daddr,
            packet.header.proto,
            packet.data,
        ) != 0) return error.BadChecksum;
        const header = Header.fromBytes(packet.data);
        return .{
            .header = header,
            .data = packet.data[header.dataOffset()..],
        };
    }
};

ip: *IPv4,
allocator: std.mem.Allocator,
listenning: std.AutoHashMap(ConnKey, *Connection),
connections: std.AutoHashMap(ConnKey, *Connection),
pub fn init(allocator: std.mem.Allocator, ip: *IPv4) Self {
    return .{
        .ip = ip,
        .allocator = allocator,
        .listenning = std.AutoHashMap(ConnKey, *Connection).init(allocator),
        .connections = std.AutoHashMap(ConnKey, *Connection).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.listenning.deinit();
    self.connections.deinit();
}

pub fn handler(self: *Self) IPv4.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

pub fn segmentRST(header: *const Header) Header {
    return std.mem.zeroInit(Header, .{
        .seq = if (header.rsv_flags.ack) header.ack else 0,
        .ack = std.mem.nativeToBig(
            u32,
            std.mem.bigToNative(u32, header.seq) + 1,
        ),
        .sport = header.dport,
        .dport = header.sport,
        .rsv_flags = .{
            .ack = true,
            .rst = true,
            .doff = @as(u4, @truncate(@sizeOf(Header) / 4)),
        },
    });
}

pub fn addConnection(self: *Self, conn: *Connection) !void {
    var mapping = switch (conn.state) {
        .LISTEN => &self.listenning,
        .CLOSED => return error.ConnectionClosed,
        else => &self.connections,
    };

    if (mapping.get(conn.id)) |_| return error.ConnectionReuse;
    try mapping.put(conn.id, conn);
}

pub fn removeConnection(self: *Self, conn: *Connection) void {
    _ = switch (conn.state) {
        .LISTEN => self.listenning.remove(conn.id),
        else => self.connections.remove(conn.id),
    };
}

pub fn handle(self: *Self, packet: *const IPv4.Packet) void {
    const segment = Segment.fromPacket(packet) catch |err| {
        std.debug.print("[TCP] Discarding packet with error {}\n", .{err});
        return;
    };

    std.debug.print("[TCP] SEQ={d}, ACK={d}, LEN={d}, SYN={}, ACK={}, FIN={}, RST={}\n", .{
        std.mem.bigToNative(u32, segment.header.seq),
        std.mem.bigToNative(u32, segment.header.ack),
        segment.data.len,
        segment.header.rsv_flags.syn,
        segment.header.rsv_flags.ack,
        segment.header.rsv_flags.fin,
        segment.header.rsv_flags.rst,
    });
    const id: ConnKey = .{
        .saddr = packet.header.saddr,
        .sport = segment.header.sport,
        .daddr = packet.header.daddr,
        .dport = segment.header.dport,
    };

    if (self.connections.get(id)) |conn| {
        conn.handleSegment(&packet.header, &segment);
        return;
    } else if (self.listenning.get(.{
        .dport = segment.header.dport,
        .daddr = packet.header.daddr,
    })) |conn| {
        if (segment.header.rsv_flags.syn) {
            conn.handleSegment(&packet.header, &segment);
        }
        return;
    }

    // "If the state is CLOSED (i.e., TCB does not exist) then all data in the
    // incoming segment is discarded."

    if (segment.header.rsv_flags.rst) {
        // "An incoming segment containing a RST is discarded."
        return;
    } else {
        // "An incoming segment not containing a RST causes a RST to be sent in
        // response."
        var rst = segmentRST(&segment.header);
        rst.csum = rst.checksum(
            packet.header.saddr,
            packet.header.daddr,
            packet.header.proto,
            "",
        );
        self.ip.send(
            null,
            packet.header.saddr,
            .TCP,
            std.mem.asBytes(&rst),
        ) catch return;
    }
}

fn vhandle(ctx: *anyopaque, packet: *const IPv4.Packet) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(packet);
}
