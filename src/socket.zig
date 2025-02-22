const std = @import("std");

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Utils = @import("utils.zig");
const Options = @import("options.zig");
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
canread: std.Thread.Condition,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, tcp: *TCP) Self {
    return .{
        .tcp = tcp,
        .addr = 0,
        .port = 0,
        .conn = null,
        .mutex = .{},
        .events = .{},
        .canread = .{},
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

fn _accepted(self: *Self, pending: *const Connection.Incoming) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    self.addr = pending.id.saddr;
    self.port = pending.id.sport;
    self.conn = try self.allocator.create(Connection);
    if (self.conn) |conn| {
        conn.init(self.allocator, self);
        conn.context.irs = std.mem.bigToNative(u32, pending.header.seq);
        conn.context.recvNext = conn.context.irs + 1;
        try conn.setActive(
            .SYN_RECEIVED,
            pending.id.saddr,
            pending.id.sport,
            pending.id.daddr,
            pending.id.dport,
        );

        try conn.transmit(
            conn.context.recvNext,
            .{ .ack = true, .syn = true },
            "",
        );
        // wait for ACK to establish connection
        if (try conn.waitChange(.SYN_RECEIVED, -1) == .CLOSED)
            return error.AcceptFailed;
    }
}

pub fn accept(self: *Self) !*Self {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.state() != .LISTEN) return error.NotListenning;

    while (self.events.read == 0) {
        self.canread.wait(&self.mutex);
    }

    if (self.conn.?.nextPending()) |pending| {
        defer self.events.read -= 1;
        var client = try self.allocator.create(Self);
        client.* = Self.init(self.allocator, self.tcp);
        errdefer {
            client.deinit();
            self.allocator.destroy(client);
        }
        try client._accepted(&pending);
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

        try conn.transmit(null, .{ .syn = true }, "");

        if (try conn.waitChange(.SYN_SENT, -1) == .CLOSED) {
            std.debug.print("Closed\n", .{});
            return error.ConnectionRefused;
        }
    }
}

pub fn setOption(self: *Self, kind: Options.Kind, value: Options.Option) void {
    // TODO:
    _ = .{ self, kind, value };
}

pub fn state(self: Self) Connection.State {
    return if (self.conn) |conn| conn.state else .CLOSED;
}

pub fn listen(self: *Self, host: []const u8, port: u16, backlog: usize) !void {
    if (self.conn) |_| return error.ConnectionReuse;
    self.addr = try Utils.pton(host);
    self.port = std.mem.nativeToBig(u16, port);
    self.conn = try self.allocator.create(Connection);
    if (self.conn) |conn| {
        conn.init(self.allocator, self);
        try conn.setPassive(self.addr, self.port, backlog);
    }
}

pub fn read(self: *Self, buffer: []u8) !usize {
    if (self.state() == .CLOSED) return error.NotConnected;
    return try self.conn.?.received.getData(buffer);
}

pub fn write(self: *Self, buffer: []const u8) !usize {
    if (self.state() == .CLOSED) return error.NotConnected;
    // TODO: block if events.write is 0
    // TODO: add to outgoing buffer instead of sending right away
    try self.conn.?.transmit(
        self.conn.?.context.recvNext,
        .{ .ack = true, .psh = true },
        buffer,
    );
    return buffer.len;
}
