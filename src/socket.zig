const std = @import("std");

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Utils = @import("utils.zig");
const Connection = @import("conn.zig");

const Self = @This();

pub const Events = struct {
    read: u32 = 0,
    write: u32 = 0,
};

tcp: *TCP,
addr: u32,
port: u16,
conn: ?*Connection,
mutex: std.Thread.Mutex,
events: Events,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, tcp: *TCP) Self {
    return .{
        .tcp = tcp,
        .addr = 0,
        .port = 0,
        .conn = null,
        .mutex = .{},
        .events = .{},
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    if (self.conn) |conn| {
        conn.deinit();
        self.allocator.destroy(conn);
    }
    self.conn = null;
}

pub fn close(self: *Self) void {
    if (self.state() == .CLOSED) return;
    std.debug.print("Closing connection!\n", .{});
    switch (self.state()) {
        .ESTABLISHED, .SYN_SENT => {
            // TODO: send FIN
            self.addr = 0;
            self.port = 0;
            self.deinit();
        },
        else => return,
    }
}

fn _accepted(self: *Self, id: *const Connection.Id, seg: *const TCP.Segment) !void {
    self.addr = id.saddr;
    self.port = id.sport;
    self.conn = try self.allocator.create(Connection);
    if (self.conn) |conn| {
        conn.init(self.allocator, self);
        conn.context.irs = std.mem.bigToNative(u32, seg.header.seq);
        conn.context.recvNext = conn.context.irs + 1;
        try conn.setActive(
            .SYN_RECEIVED,
            id.saddr,
            id.sport,
            id.daddr,
            id.dport,
        );
        var ack: TCP.Header = std.mem.zeroInit(TCP.Header, .{
            .rsv_flags = .{
                .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                .ack = true,
                .syn = true,
            },
            .ack = std.mem.nativeToBig(u32, conn.context.recvNext),
        });

        try conn.transmit(&ack, "");
        // after transmiting the SYN-ACK, we increment SND.NXT by 1
        conn.context.sendNext += 1;
    }
}

pub fn accept(self: *Self) !*Self {
    // TODO: block if events.read is 0
    if (self.state() != .LISTEN) return error.NotListenning;
    if (self.events.read == 0) return error.NotPending;
    var entries = self.conn.?.pending.?.iterator();
    if (entries.next()) |kv| {
        defer self.events.read -= 1;
        var client = try self.allocator.create(Self);
        client.* = Self.init(self.allocator, self.tcp);
        errdefer |err| {
            client.deinit();
            self.allocator.destroy(client);
            std.debug.print("Error: {}\n", .{err});
            // for debug only:
            unreachable;
        }
        try client._accepted(kv.key_ptr, kv.value_ptr);
        _ = self.conn.?.pending.?.remove(kv.key_ptr.*);
        return client;
    }
    return error.NotPending;
}

pub fn connect(self: *Self, host: []const u8, port: u16) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    self.addr = try Utils.pton(host);
    self.port = std.mem.nativeToBig(u16, port);
    self.conn = try self.allocator.create(Connection);
    const sport = std.mem.nativeToBig(
        u16,
        std.crypto.random.intRangeAtMost(u16, 1025, 65535),
    );
    if (self.conn) |conn| {
        conn.init(self.allocator, self);
        try conn.setActive(
            .SYN_SENT,
            self.addr,
            self.port,
            self.tcp.ip.ethernet.dev.ipaddr,
            sport,
        );

        var ack: TCP.Header = std.mem.zeroInit(TCP.Header, .{
            .sport = sport,
            .dport = self.port,
            .rsv_flags = .{
                .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                .syn = true,
            },
        });

        try conn.transmit(&ack, "");
        conn.context.sendNext += 1;

        // std.debug.print("State before: {}\n", .{conn.state});
        while (conn.state == .SYN_SENT) {
            conn.changed.wait(&self.mutex);
        }
        // std.debug.print("State after: {}\n", .{conn.state});
        if (conn.state == .CLOSED) {
            self.deinit();
            return error.ConnectionRefused;
        }
    }
}

pub fn state(self: Self) Connection.State {
    return if (self.conn) |conn| conn.state else .CLOSED;
}

pub fn listen(self: *Self, host: []const u8, port: u16) !void {
    if (self.conn) |_| return error.ConnectionReuse;
    self.addr = try Utils.pton(host);
    self.port = std.mem.nativeToBig(u16, port);
    self.conn = try self.allocator.create(Connection);
    self.conn.?.init(self.allocator, self);
    try self.conn.?.setPassive(self.addr, self.port);
}

pub fn read(self: *Self, buffer: []u8) !usize {
    if (self.state() == .CLOSED) return error.NotConnected;
    return try self.conn.?.received.getData(buffer);
}

pub fn write(self: *Self, buffer: []const u8) !usize {
    // TODO: block if events.write is 0
    // TODO: add to outgoing buffer instead of sending right away
    var hdr = std.mem.zeroInit(TCP.Header, .{
        .rsv_flags = .{
            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
            .ack = true,
            .psh = true,
        },
        .ack = std.mem.nativeToBig(u32, self.conn.?.context.recvNext),
    });
    try self.conn.?.transmit(&hdr, buffer);
    return buffer.len;
}
