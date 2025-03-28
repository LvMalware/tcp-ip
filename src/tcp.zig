const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const IPv4 = @import("ipv4.zig");
const Option = @import("options.zig").Option;
const Connection = @import("conn.zig");
const ConnKey = Connection.Id;
const SendQueue = @import("sendqueue.zig");

const Self = @This();

const vtable = IPv4.Handler.VTable{ .handle = vhandle };

pub const Flags = switch (native_endian) {
    .big => packed struct {
        doff: u4 = @truncate(@sizeOf(Header) / 4),
        rsv: u4 = 0,
        cwr: bool = false,
        ece: bool = false,
        urg: bool = false,
        ack: bool = false,
        psh: bool = false,
        rst: bool = false,
        syn: bool = false,
        fin: bool = false,
    },
    .little => packed struct {
        rsv: u4 = 0,
        doff: u4 = @truncate(@sizeOf(Header) / 4),
        fin: bool = false,
        syn: bool = false,
        rst: bool = false,
        psh: bool = false,
        ack: bool = false,
        urg: bool = false,
        ece: bool = false,
        cwr: bool = false,
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
    flags: Flags align(1), // data offset, reserved bits and flags
    window: u16 align(1),
    csum: u16 align(1),
    urgent: u16 align(1),

    pub fn fromBytes(bytes: []const u8) Header {
        return std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
    }

    pub fn checksum(self: Header, saddr: u32, daddr: u32, proto: u8, data: []const u8) u16 {
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
        return @as(usize, self.flags.doff) * 4;
    }
};

pub const Segment = struct {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: Flags,
    window: u16,
    csum: u16,
    urgent: u16,
    options: []Option,
    data: []const u8,

    pub fn fromPacket(allocator: std.mem.Allocator, packet: *const IPv4.Packet) !Segment {
        if (tcpChecksum(packet.header.saddr, packet.header.daddr, packet.header.proto, packet.data) != 0)
            return error.BadChecksum;

        const header = Header.fromBytes(packet.data);
        var segment: Segment = undefined;

        inline for (std.meta.fields(Header)) |field| {
            @field(segment, field.name) = if (field.type == u32)
                std.mem.bigToNative(u32, @field(header, field.name))
            else
                @field(header, field.name);
        }

        var options = std.ArrayList(Option).init(allocator);
        defer options.deinit();

        var index: usize = @sizeOf(Header);
        while (index < header.dataOffset()) {
            const option = Option.fromBytes(packet.data[index..]) catch break;
            try options.append(option);
            index += option.size();
            if (option == .END) break;
        }

        segment.options = try options.toOwnedSlice();
        segment.data = packet.data[header.dataOffset()..];

        return segment;
    }

    pub fn getHeader(self: Segment) Header {
        var header: Header = undefined;
        inline for (std.meta.fields(Header)) |field| {
            @field(header, field.name) = @field(self, field.name);
        }
        return header;
    }

    pub fn deinit(self: Segment, allocator: std.mem.Allocator) void {
        allocator.free(self.options);
    }
};

ip: *IPv4,
rto: usize,
mutex: std.Thread.Mutex,
sendqueue: SendQueue,
allocator: std.mem.Allocator,
transmission: ?std.Thread,
listenning: std.AutoHashMap(ConnKey, *Connection),
connections: std.AutoHashMap(ConnKey, *Connection),

pub fn init(allocator: std.mem.Allocator, ip: *IPv4, rto: usize) !*Self {
    const tcp = try allocator.create(Self);
    tcp.* = .{
        .ip = ip,
        .rto = rto * std.time.ns_per_ms,
        .mutex = .{},
        .sendqueue = try SendQueue.init(allocator, rto * std.time.ns_per_ms),
        .allocator = allocator,
        .listenning = std.AutoHashMap(ConnKey, *Connection).init(allocator),
        .connections = std.AutoHashMap(ConnKey, *Connection).init(allocator),
        .transmission = null,
    };

    tcp.transmission = try std.Thread.spawn(.{}, transmissionLoop, .{tcp});
    return tcp;
}

pub fn deinit(self: *Self) void {
    defer self.allocator.destroy(self); // ---> defer first, executes last
    self.mutex.lock();
    defer self.mutex.unlock(); //          ---> defer last, executes first

    self.sendqueue.deinit();

    if (self.transmission) |*thread| thread.join();

    self.listenning.deinit();
    self.connections.deinit();
}

pub fn handler(self: *Self) IPv4.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

fn transmissionLoop(self: *Self) void {
    while (self.sendqueue.dequeue()) |item| {
        // simulate random packet loss:
        // if (std.crypto.random.boolean()) {
        //     std.debug.print("Losing packet {d}...\n", .{item.segend});
        //     continue;
        // }
        self.ip.send(null, item.conn.saddr, .TCP, item.segment) catch continue;
    }
}

pub fn addConnection(self: *Self, conn: *Connection) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var mapping = switch (conn.state) {
        .LISTEN => &self.listenning,
        .CLOSED => return error.ConnectionClosed,
        else => &self.connections,
    };

    if (mapping.get(conn.id)) |_| return error.ConnectionReuse;
    try mapping.put(conn.id, conn);
}

pub fn removeConnection(self: *Self, conn: *Connection) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    _ = switch (conn.state) {
        .LISTEN => self.listenning.remove(conn.id),
        // .TIME_WAIT => wait 2*MSL before removing
        else => self.connections.remove(conn.id),
    };
}

pub fn handle(self: *Self, packet: *const IPv4.Packet) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    const segment = Segment.fromPacket(self.allocator, packet) catch |err| {
        std.debug.print("[TCP] Discarding packet with error {}\n", .{err});
        return;
    };

    defer segment.deinit(self.allocator);

    std.debug.print("[TCP] SEQ={d}, ACK={d}, LEN={d}, SYN={}, ACK={}, FIN={}, RST={}\n", .{
        segment.seq,
        segment.ack,
        segment.data.len,
        segment.flags.syn,
        segment.flags.ack,
        segment.flags.fin,
        segment.flags.rst,
    });

    if (self.connections.get(.{
        .saddr = packet.header.saddr,
        .sport = segment.sport,
        .daddr = packet.header.daddr,
        .dport = segment.dport,
    })) |conn| {
        // std.debug.print("Delivering packet to active connection\n", .{});
        conn.handleSegment(&packet.header, &segment);
        return;
    } else if (self.listenning.get(.{
        .dport = segment.dport,
        .daddr = packet.header.daddr,
    })) |conn| {
        if (segment.flags.syn) {
            // std.debug.print("Delivering packet to passive connection\n", .{});
            conn.handleSegment(&packet.header, &segment);
            return;
        }
    }

    std.debug.print("[TCP] Discarding packet with RST\n", .{});

    // "If the state is CLOSED (i.e., TCB does not exist) then all data in the
    // incoming segment is discarded."

    if (segment.flags.rst) {
        // "An incoming segment containing a RST is discarded."
        return;
    } else {
        // "An incoming segment not containing a RST causes a RST to be sent in
        // response."

        var rst = std.mem.zeroInit(Header, .{
            .seq = if (segment.flags.ack) segment.ack else 0,
            .ack = std.mem.nativeToBig(u32, segment.seq + 1),
            .sport = segment.dport,
            .dport = segment.sport,
            .flags = .{
                .ack = true,
                .rst = true,
            },
        });

        rst.csum = rst.checksum(
            packet.header.saddr,
            packet.header.daddr,
            packet.header.proto,
            "",
        );

        self.ip.send(null, packet.header.saddr, .TCP, std.mem.asBytes(&rst)) catch return;
    }
}

fn vhandle(ctx: *anyopaque, packet: *const IPv4.Packet) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(packet);
}
