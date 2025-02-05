const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const IPv4 = @import("ipv4.zig");
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

pub const ConnKey = struct {
    saddr: u32 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    dport: u16 = 0,
};

pub const Connection = struct {
    // TCB struct
    testing: bool,
};

pub fn tcpChecksum(saddr: u32, daddr: u32, proto: u8, data: []const u8) u16 {
    var csum: u32 = 0;
    csum += saddr;
    csum += daddr;
    csum += std.mem.nativeToBig(u16, proto);
    csum += std.mem.nativeToBig(u16, @truncate(data.len));

    for (std.mem.bytesAsSlice(u16, data)) |w| {
        csum += w;
    }

    while (csum >> 16 != 0) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return @truncate(~csum);
}

const Header = extern struct {
    sport: u16 align(1),
    dport: u16 align(1),
    seq: u32 align(1),
    ack: u32 align(1),
    rsv_flags: RsvFlags align(1), // data offset, reserved bytes and flags
    window: u16 align(1),
    csum: u16 align(1),
    urgent: u16 align(1),
    optpad: u32 align(1), // options and padding

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

        for (std.mem.bytesAsSlice(u16, data)) |w| {
            csum += w;
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

const Segment = struct {
    header: Header,
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
listenning: std.AutoHashMap(ConnKey, Connection),
connections: std.AutoHashMap(ConnKey, Connection),
pub fn init(allocator: std.mem.Allocator, ip: *IPv4) Self {
    return .{
        .ip = ip,
        .allocator = allocator,
        .listenning = std.AutoHashMap(ConnKey, Connection).init(allocator),
        .connections = std.AutoHashMap(ConnKey, Connection).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.listenning.deinit();
    self.connections.deinit();
}

pub fn handler(self: *Self) IPv4.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

fn segmentRST(header: *const Header) Header {
    return .{
        .seq = if (header.rsv_flags.ack) header.ack else 0,
        .ack = std.mem.nativeToBig(
            u32,
            std.mem.bigToNative(u32, header.seq) + 1,
        ),
        .sport = header.dport,
        .dport = header.sport,
        .urgent = header.urgent,
        .window = 0,
        .csum = 0,
        .optpad = 0,
        .rsv_flags = .{
            .rsv = 0,
            .ack = true,
            .rst = true,
            .fin = false,
            .syn = false,
            .psh = false,
            .urg = false,
            .ece = false,
            .cwr = false,
            .doff = @truncate(@sizeOf(Header) / 4),
        },
    };
}

pub fn handle(self: *Self, packet: *const IPv4.Packet) void {
    const segment = Segment.fromPacket(packet) catch |err| {
        std.debug.print("[TCP] Discarding packet with error {}\n", .{err});
        return;
    };

    std.debug.print("[TCP] SEQ={d}, ACK={d}, LEN={d}, SYN={}, ACK={}\n", .{
        segment.header.seq,
        segment.header.ack,
        segment.data.len,
        segment.header.rsv_flags.syn,
        segment.header.rsv_flags.ack,
    });

    if (self.connections.get(.{
        .saddr = packet.header.saddr,
        .sport = segment.header.sport,
        .daddr = packet.header.daddr,
        .dport = segment.header.dport,
    })) |*conn| {
        std.debug.print("Packet belongs to connection {}\n", .{conn});
    } else if (self.listenning.get(.{
        .dport = segment.header.dport,
        .daddr = packet.header.daddr,
    })) |*connection| {
        std.debug.print("Passive connection {}\n", .{connection});
    } else {
        std.debug.print(
            "[TCP] Incoming segment to invalid connection. Sending RST\n",
            .{},
        );
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
