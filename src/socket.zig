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
    var old = self.state();
    self.close();
    if (self.conn) |conn| {
        while (old != .CLOSED) {
            // TODO: TIME_WAIT
            std.debug.print("Looping on deinit: {}...\n", .{old});
            old = conn.waitChange(old, -1) catch continue;
        }
        conn.deinit();
        self.allocator.destroy(conn);
        self.conn = null;
    }
}

pub fn close(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    switch (self.state()) {
        .CLOSED, .LISTEN, .SYN_SENT => {},
        .SYN_RECEIVED => {
            // If no SENDs have been issued and there is no pending data to send,
            // then form a FIN segment and send it, and enter FIN-WAIT-1 state;
            // otherwise queue for processing after entering ESTABLISHED state.
            if (self.conn) |conn| {
                if (self.tcp.sendqueue.countPending(conn.id) >= 0) {
                    _ = conn.waitChange(.SYN_RECEIVED, -1) catch {};
                }
                conn.transmit(
                    null,
                    .{ .fin = true, .ack = true },
                    "",
                ) catch {};
            }
            return;
        },
        .FIN_WAIT1, .FIN_WAIT2 => {
            // Strictly speaking, this is an error and should receive a "error:
            // connection closing" response.  An "ok" response would be
            // acceptable, too, as long as a second FIN is not emitted (the first
            // FIN may be retransmitted though).
            return;
        },
        .LAST_ACK => {
            std.debug.assert(
                self.conn.?.waitChange(.LAST_ACK, -1) catch .CLOSED == .CLOSED,
            );
        },
        .CLOSING, .TIME_WAIT => {
            // Respond with "error:  connection closing".
            return;
        },
        .ESTABLISHED => {
            // Queue this until all preceding SENDs have been segmentized, then
            // form a FIN segment and send it.  In any case, enter FIN-WAIT-1
            // state.
            self.conn.?.transmit(
                null,
                .{ .fin = true, .ack = true },
                "",
            ) catch {};
            return;
        },
        .CLOSE_WAIT => {
            // Queue this request until all preceding SENDs have been
            // segmentized; then send a FIN segment, enter CLOSING state.
            self.conn.?.transmit(
                null,
                .{ .fin = true, .ack = true },
                "",
            ) catch {};
            _ = self.conn.?.waitChange(.LAST_ACK, -1) catch unreachable;
            return;
        },
    }

    if (self.conn) |conn| {
        conn.deinit();
        self.allocator.destroy(conn);
    }

    self.conn = null;
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
        for (pending.options) |opt| {
            switch (opt) {
                .MSS => |mss| conn.context.mss = mss.data,
                else => continue,
            }
        }
        conn.context.recvNext = conn.context.irs + 1;
        try conn.setActive(
            .SYN_RECEIVED,
            pending.id.saddr,
            pending.id.sport,
            pending.id.daddr,
            pending.id.dport,
        );

        const opt = Options.MSSOption{
            .data = conn.context.mss,
        };
        const mss = try self.allocator.alloc(u8, opt.size());
        defer self.allocator.free(mss);
        opt.toBytes(mss[0..]);
        const doff = mss.len + @sizeOf(TCP.Header);

        try conn.transmit(
            conn.context.recvNext,
            .{ .doff = @truncate(doff / 4), .ack = true, .syn = true },
            mss,
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
    if (self.state() != .CLOSED) return error.SocketInUse;
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

        const opt = Options.MSSOption{
            .data = conn.context.mss,
        };
        const mss = try self.allocator.alloc(u8, opt.size());
        defer self.allocator.free(mss);
        const doff = mss.len + @sizeOf(TCP.Header);

        opt.toBytes(mss[0..]);

        try conn.transmit(
            null,
            .{ .doff = @truncate(doff / 4), .syn = true },
            mss,
        );

        if (try conn.waitChange(.SYN_SENT, 30 * std.time.ns_per_s) == .CLOSED) {
            // std.debug.print("Closed\n", .{});
            return error.ConnectionRefused;
        }
    }
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
    return switch (self.state()) {
        .CLOSED, .LISTEN => error.NotConnected,
        .CLOSING, .LAST_ACK, .TIME_WAIT => error.Closing,
        .CLOSE_WAIT => {
            const size = if (buffer.len > self.conn.?.received.contiguous_len)
                self.conn.?.received.contiguous_len
            else
                buffer.len;
            return try self.conn.?.received.getData(buffer[0..size]);
        },
        else => try self.conn.?.received.getData(buffer),
    };
}

pub fn write(self: *Self, buffer: []const u8) !usize {
    const current = self.state();
    switch (current) {
        .CLOSED => return error.NotConnected,
        .FIN_WAIT1, .FIN_WAIT2, .CLOSING, .LAST_ACK, .TIME_WAIT => {
            return error.Closing;
        },
        .ESTABLISHED => {},
        else => {
            // wait until connection is established
            while (try self.conn.?.waitChange(current, -1) != .ESTABLISHED) {}
        },
    }

    var sent: usize = 0;
    if (self.conn) |conn| {
        const mss = conn.getMSS();
        var slices = std.mem.window(u8, buffer, mss, mss);
        while (slices.next()) |slice| {
            conn.mutex.lock();
            defer conn.mutex.unlock();
            const limit = if (conn.usableWindow() > slice.len)
                slice.len
            else
                conn.usableWindow();

            if (limit == 0) break;

            try conn.transmit(
                conn.context.recvNext,
                .{
                    .ack = true,
                    .psh = (slices.index orelse 0 + mss) >= buffer.len,
                },
                slice[0..limit],
            );
            sent += limit;
        }
    }
    return sent;
}
