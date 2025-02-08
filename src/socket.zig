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
events: Events,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, tcp: *TCP) Self {
    return .{
        .tcp = tcp,
        .addr = 0,
        .port = 0,
        .conn = null,
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
    switch (self.state()) {
        .ESTABLISHED => {
            // TODO: send FIN
            self.addr = 0;
            self.port = 0;
            self.deinit();
        },
        else => return,
    }
}

fn _accepted(self: *Self, id: *const Connection.Id, seg: *const TCP.Segment) !void {
    std.debug.print("Accepting connection from: {d}\n", .{id.saddr});
    self.addr = id.saddr;
    self.port = id.sport;
    self.conn = try self.allocator.create(Connection);
    if (self.conn) |conn| {
        try conn.init(self.allocator, self);
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
    }
}

pub fn accept(self: *Self) !Self {
    // TODO: block if events.read is 0
    if (self.events.read == 0) return error.NotPending;
    if (self.state() != .LISTEN) return error.NotListenning;
    var entries = self.conn.?.pending.?.iterator();
    if (entries.next()) |kv| {
        defer self.events.read -= 1;
        var client = Self.init(self.allocator, self.tcp);
        errdefer |err| {
            client.deinit();
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
    // TODO
    _ = .{ self, host, port };
}

pub fn state(self: Self) Connection.State {
    if (self.conn) |conn| return conn.state;
    return .CLOSED;
}

pub fn listen(self: *Self, host: []const u8, port: u16) !void {
    if (self.conn) |_| return error.ConnectionReuse;
    self.addr = try Utils.pton(host);
    self.port = std.mem.nativeToBig(u16, port);
    self.conn = try self.allocator.create(Connection);
    try self.conn.?.init(self.allocator, self);
    try self.conn.?.setPassive(self.addr, self.port);
}

// cur_seq == prev_seq + len
// xxxx|----|xxxx|----|----|----
//     ^    ^
pub fn read(self: *Self, buffer: []u8) !usize {
    // TODO: block until data is available
    if (self.events.read < 1) return error.WouldBlock;
    // self.conn.receive_buffer
    return buffer.len;
}
