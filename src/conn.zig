const std = @import("std");

const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Socket = @import("socket.zig");
const Sorted = @import("sorted.zig");
const Option = @import("options.zig").Option;

const Self = @This();

// maximum segment lifetime
pub const default_msl = 2 * std.time.ns_per_min;
// maximum segment size
pub const default_mss = 1460;
// receive window size
pub const default_window = 64256;

pub const Id = struct {
    saddr: u32 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    dport: u16 = 0,
    pub fn eql(self: Id, other: Id) bool {
        return self.saddr == other.saddr and self.sport == other.sport and
            self.daddr == other.daddr and self.dport == other.dport;
    }
};

const Context = struct {
    irs: u32 = 0,
    iss: u32 = 0,
    mss: u16 = default_mss, // maximum segment size
    sendNext: u32 = 0, // sequence id of next segment to be sent
    recvNext: u32 = 0, // sequence id of next segment to be received
    sendUnack: u32 = 0, // oldest unacknowledged segment
    sendUrgent: u32 = 0, // sent urgent data pointer
    recvUrgent: u32 = 0, // received urgent data pointer
    sendWinSeq: u32 = 0, // sequence id of last window update segment
    sendWinAck: u32 = 0, // ack id of last window update segment
    sendWindow: u16 = 0, // remote host's recvWindow
    recvWindow: u16 = default_window, // this host's recvWindow
};

pub const Incoming = struct {
    id: Id,
    header: TCP.Header,
    options: []Option,
};

pub const State = enum(u8) {
    CLOSED,
    LISTEN,
    CLOSING,
    SYN_SENT,
    LAST_ACK,
    TIME_WAIT,
    FIN_WAIT1,
    FIN_WAIT2,
    CLOSE_WAIT,
    ESTABLISHED,
    SYN_RECEIVED,
};

pub const Mode = enum(u8) {
    NORMAL,
    URGENT,
};

id: Id,
tcp: *TCP,
mode: Mode = .NORMAL,
sock: *Socket,
mutex: std.Thread.Mutex,
state: State = .CLOSED,
empty: std.Thread.Condition,
backlog: usize,
changed: std.Thread.Condition,
context: Context,
pending: u32 = 0,
accepts: std.DoublyLinkedList(Incoming),
received: Sorted,
allocator: std.mem.Allocator,

pub fn init(self: *Self, allocator: std.mem.Allocator, sock: *Socket) void {
    const iss = std.crypto.random.int(u32);

    self.* = .{
        .id = undefined,
        .tcp = sock.tcp,
        .sock = sock,
        .mutex = .{},
        .empty = .{},
        .backlog = 128,
        .changed = .{},
        .accepts = .{},
        .pending = 0,
        .context = .{
            .iss = iss,
            .sendNext = iss,
            .sendUnack = iss,
        },
        .received = Sorted.init(allocator),
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    self.received.deinit();
    self.tcp.removeConnection(self);
    self.tcp.sendqueue.removeAll(self.id);
    while (self.accepts.pop()) |node| {
        self.allocator.free(node.data.options);
        self.allocator.destroy(node);
    }
    self.state = .CLOSED;
    self.changed.signal();
}

pub fn getMSS(self: Self) u16 {
    return self.context.mss - @sizeOf(TCP.Header);
}

pub fn usableWindow(self: *Self) u16 {
    const diff = @subWithOverflow(self.context.sendNext, self.context.sendUnack);
    return self.context.sendWindow - @as(u16, @truncate(
        if (diff[1] == 0) diff[0] else (std.math.maxInt(u32) - self.context.sendUnack) + self.context.sendNext,
    ));
}

pub fn waitChange(self: *Self, state: State, timeout: isize) !State {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.state != state) return self.state;
    try self.changed.timedWait(&self.mutex, @bitCast(timeout));
    return self.state;
}

pub fn waitSendAll(self: *Self, timeout: isize) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.pending > 0)
        try self.empty.timedWait(&self.mutex, @bitCast(timeout));
}

pub fn transmit(self: *Self, ack: ?u32, flags: TCP.Flags, data: []const u8) !void {
    const segLen = @sizeOf(TCP.Header) + data.len;
    if (segLen > self.context.mss or (self.context.sendWindow > 0 and segLen > self.usableWindow()))
        return error.SegmentTooBig;

    var header = std.mem.zeroInit(TCP.Header, .{
        .seq = nativeToBig(u32, self.context.sendNext),
        .ack = nativeToBig(
            u32,
            ack orelse @truncate(
                self.received.ackable() orelse self.context.recvNext,
            ),
        ),
        .csum = 0,
        .flags = flags,
        .sport = self.id.dport,
        .dport = self.id.sport,
        .window = nativeToBig(u16, self.context.recvWindow),
    });

    header.csum = header.checksum(
        self.id.daddr,
        self.id.saddr,
        @intFromEnum(IPv4.Proto.TCP),
        data,
    );

    const buffer = try self.allocator.alloc(u8, @sizeOf(TCP.Header) + data.len);
    std.mem.copyForwards(u8, buffer[0..], std.mem.asBytes(&header));

    const dataLen = buffer.len - header.dataOffset();

    if (header.dataOffset() > @sizeOf(TCP.Header)) {
        std.mem.copyForwards(u8, buffer[@sizeOf(TCP.Header)..], data);
    } else {
        std.mem.copyForwards(u8, buffer[header.dataOffset()..], data);
    }

    if ((header.flags.syn or header.flags.fin) and dataLen == 0) {
        // after transmiting a FIN or a SYN, we increment snd.nxt by 1
        self.context.sendNext = @addWithOverflow(self.context.sendNext, 1)[0];
    } else {
        // only increment snd.nxt by the amount of data sent
        self.context.sendNext = @truncate(@addWithOverflow(self.context.sendNext, dataLen)[0]);
    }

    if (flags.fin) {
        switch (self.state) {
            .CLOSE_WAIT => {
                self.state = .LAST_ACK;
                self.changed.signal();
            },
            .SYN_RECEIVED, .ESTABLISHED => {
                self.state = .FIN_WAIT1;
                self.changed.signal();
            },
            else => {},
        }
    }

    if (!flags.rst and (!flags.ack or dataLen > 0)) {
        try self.tcp.sendqueue.enqueue(
            buffer,
            self.id,
            self.context.sendNext,
        );
        self.pending += 1;
    } else {
        try self.tcp.ip.send(null, self.id.saddr, .TCP, buffer);
    }
}

pub fn nextAccept(self: *Self) ?Incoming {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.accepts.popFirst()) |node| {
        defer self.allocator.destroy(node);
        return node.data;
    }
    return null;
}

fn addAccept(self: *Self, ip: *const IPv4.Header, seg: *const TCP.Segment) !void {
    var next = self.accepts.first;
    while (next != null) : (next = next.?.next) {
        if (ip.saddr == next.?.data.id.saddr and seg.sport == next.?.data.id.sport)
            return;
    }

    const node = self.allocator.create(std.DoublyLinkedList(Incoming).Node) catch return;

    node.data = .{
        .id = .{
            .saddr = ip.saddr,
            .sport = seg.sport,
            .daddr = ip.daddr,
            .dport = seg.dport,
        },
        .header = seg.getHeader(),
        .options = self.allocator.dupe(Option, seg.options) catch {
            self.allocator.destroy(node);
            return;
        },
    };

    self.accepts.append(node);

    self.sock.read_event.post();
}

pub fn setPassive(self: *Self, addr: u32, port: u16, backlog: usize) !void {
    if (self.state != .CLOSED) return error.ConnectionReused;
    self.id = .{
        .daddr = addr,
        .dport = port,
    };
    self.state = .LISTEN;
    self.changed.signal();
    self.backlog = backlog;
    try self.tcp.addConnection(self);
}

pub fn acceptable(self: Self, segment: *const TCP.Segment) bool {
    const winLimit = self.context.recvNext + self.context.recvWindow;

    if (self.context.recvWindow == 0) {
        return segment.data.len == 0 and segment.seq == self.context.recvNext;
    } else if (segment.data.len == 0) {
        return self.context.recvNext <= segment.seq and segment.seq < winLimit;
    }

    const dataEnd = segment.seq + segment.data.len - 1;

    return (self.context.recvNext <= segment.seq and segment.seq < winLimit) or
        (self.context.recvNext <= dataEnd and dataEnd < winLimit);
}

pub fn acknowledge(self: *Self, seg: *const TCP.Segment) void {
    var seq = self.received.ackable() orelse
        seg.seq + if (seg.data.len > 0) seg.data.len else 1;

    if (seg.flags.fin) seq += 1;
    if (seq > self.context.recvNext) self.context.recvNext = @truncate(seq);

    self.transmit(@truncate(seq), .{ .ack = true }, "") catch {};
}

fn processSegmentText(self: *Self, segment: *const TCP.Segment) void {
    if (segment.data.len > 0) {
        self.received.insert(segment.seq, segment.data, segment.flags.psh or segment.flags.fin) catch return;
        self.context.recvWindow = @as(u16, @truncate(default_window - self.received.data_len));
        self.acknowledge(segment);
    }

    if (segment.flags.psh or segment.flags.fin) {
        self.sock.read_event.post();
    }

    if (segment.flags.urg) {
        const urg = @addWithOverflow(segment.seq, bigToNative(u16, segment.urgent))[0];
        if (urg > self.context.recvUrgent) {
            self.context.recvUrgent = urg;
            if (self.mode != .URGENT) {
                std.debug.print("[TCB] Going into URGENT mode until {d}\n", .{urg});
            }

            self.mode = .URGENT;
            // signal user
        }
    } else {
        self.mode = .NORMAL;
    }
}

pub fn handleSegment(self: *Self, ip: *const IPv4.Header, segment: *const TCP.Segment) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    switch (self.state) {
        .CLOSED => return,
        .LISTEN => {
            if (segment.flags.fin or segment.flags.rst)
                return;

            if (segment.flags.ack) {
                self.transmit(segment.seq + 1, .{ .rst = true, .ack = true }, "") catch {};
            } else if (segment.flags.syn) {
                // TODO: check security and precedence

                self.addAccept(ip, segment) catch {};
            }
            return;
        },
        .SYN_SENT => {
            if (segment.flags.fin) return;
            if (segment.flags.ack) {
                const ack = segment.ack;
                if (ack <= self.context.iss or ack > self.context.sendNext) {
                    if (!segment.flags.rst)
                        self.transmit(null, .{ .rst = true }, "") catch {};
                    return;
                }
                self.context.sendUnack = ack;
            }
            if (segment.flags.rst) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
            // TODO: check security and precedence
            if (segment.flags.syn) {
                self.context.irs = segment.seq;
                self.context.recvNext = self.context.irs + 1;

                if (self.context.sendUnack > self.context.iss) {
                    self.transmit(self.context.recvNext, .{ .ack = true }, "") catch return;
                    self.state = .ESTABLISHED;
                    self.changed.signal();
                } else {
                    self.state = .SYN_RECEIVED;
                    self.changed.signal();
                    self.transmit(self.context.recvNext, .{ .ack = true, .syn = true }, "") catch {};
                }
                self.context.sendWinSeq = segment.seq;
                self.context.sendWinAck = segment.ack;
                self.context.sendWindow = bigToNative(u16, segment.window);
            }
            return;
        },
        else => {}, // other states will be handled next
    }

    if (!self.acceptable(segment)) {
        if (segment.flags.rst) return;
        self.transmit(self.context.recvNext, .{ .ack = true }, "") catch {};
        return;
    }

    if (segment.flags.rst or segment.flags.syn) {
        self.state = .CLOSED;
        self.changed.signal();
        return;
    }

    const ack = if (segment.flags.ack) segment.ack else self.context.iss;

    if (segment.flags.ack) {
        self.pending -= self.tcp.sendqueue.ack(self.id, ack);
        if (self.pending == 0) self.empty.signal();
        if (ack > self.context.sendUnack and ack < self.context.sendNext)
            self.context.sendUnack = ack;
    }

    // all the following states share the same code above

    switch (self.state) {
        .CLOSING => {
            if (self.context.sendNext <= ack) {
                // TODO: start 2 MSL timeout
                self.state = .TIME_WAIT;
                self.changed.signal();
            }
            return;
        },
        .SYN_RECEIVED => {
            if (self.context.sendUnack <= ack and ack <= self.context.sendNext) {
                self.state = .ESTABLISHED;
                self.changed.signal();
            } else {
                self.transmit(segment.seq + 1, .{ .rst = true }, "") catch {};
                return;
            }
            self.context.sendWinSeq = segment.seq;
            self.context.sendWinAck = segment.ack;
            self.context.sendWindow = bigToNative(u16, segment.window);

            self.state = .ESTABLISHED;
            self.changed.signal();
        },
        .LAST_ACK => {
            if (ack >= self.context.sendNext) {
                self.state = .CLOSED;
                self.changed.signal();
            }
        },
        .TIME_WAIT => {
            if (segment.flags.fin) {
                // TODO: restart 2 MSL timeout
                self.changed.signal();
            }
        },
        .FIN_WAIT1 => {
            // a FIN without ACK is theoretically possible, but in this
            // implementation it is considered invalid and will be ignored
            if (!segment.flags.ack) return;

            if (segment.flags.fin) {
                // Both sides are trying to close simultaneously
                self.state = if (ack >= self.context.sendNext) .TIME_WAIT else .CLOSING;
                self.changed.signal();
                self.acknowledge(segment);
                return;
            }

            self.processSegmentText(segment);

            if (ack >= self.context.sendNext) {
                self.state = .FIN_WAIT2;
                self.changed.signal();
                return;
            }
        },
        .FIN_WAIT2 => {
            if (!segment.flags.ack) return;

            // "if the retransmission queue is empty, the user's CLOSE can
            // be acknowledged ("ok") but do not delete the TCB."

            if (segment.flags.fin) {
                // TODO: start 2 MSL timeout
                self.state = .TIME_WAIT;
                self.changed.signal();
                self.acknowledge(segment);
                return;
            }

            self.processSegmentText(segment);
        },
        .CLOSE_WAIT, .ESTABLISHED => {
            if (!segment.flags.ack) return;

            const seq = segment.seq;
            if (ack > self.context.sendNext) {
                std.debug.print("[TCB] Warning: ACK is bigger than sendNext!\n", .{});
                self.acknowledge(segment);
                return;
            } else if (ack < self.context.sendUnack) {
                // Maybe we retransmitted a packet already ACKed?
                std.debug.print("[TCB] Warning: ACK is less than sendUnack!\n", .{});
            } else if (self.context.sendUnack < ack) {
                if (self.context.sendWinSeq < seq or (self.context.sendWinSeq == seq and self.context.sendWinAck <= ack)) {
                    self.context.sendWinSeq = seq;
                    self.context.sendWinAck = ack;
                    self.context.sendWindow = bigToNative(u16, segment.window);
                }
            }

            self.processSegmentText(segment);

            if (segment.flags.fin) {
                if (segment.data.len == 0)
                    self.received.insert(segment.seq, "", true) catch {};

                self.state = .CLOSE_WAIT;
                self.changed.signal();

                self.acknowledge(segment);
            }
            return;
        },
        // all other states must have been handled previously
        else => unreachable,
    }
}
