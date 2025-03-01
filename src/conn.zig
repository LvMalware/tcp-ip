const std = @import("std");

const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Queue = @import("queue.zig");
const Socket = @import("socket.zig");
const Sorted = @import("sorted.zig");
const Option = @import("options.zig").Option;

const Self = @This();

pub const default_mss = 1460;
pub const default_window = 64256;

pub const Id = struct {
    saddr: u32 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    dport: u16 = 0,
};

const Context = struct {
    irs: u32 = 0,
    iss: u32 = 0,
    mss: u16 = default_mss, // maximum segment size
    sendNext: u32 = 0, // sequence id of next segment to be sent
    recvNext: u32 = 0, // sequence id of next segment to be received
    sendUnack: u32 = 0, // oldest unacknowledged segment
    sendUrgent: u16 = 0, // sent urgent data pointer
    recvUrgent: u16 = 0, // received urgent data pointer
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

id: Id,
tcp: *TCP,
sock: *Socket,
mutex: std.Thread.Mutex,
state: State = .CLOSED,
timer: std.time.Timer,
backlog: usize,
changed: std.Thread.Condition,
context: Context,
pending: std.TailQueue(Incoming),
received: Sorted,
allocator: std.mem.Allocator,
retransmission: Queue,

pub fn init(self: *Self, allocator: std.mem.Allocator, sock: *Socket) void {
    const iss = std.crypto.random.int(u32);

    self.* = .{
        .id = undefined,
        .tcp = sock.tcp,
        .sock = sock,
        .mutex = .{},
        .timer = undefined,
        .backlog = 128,
        .changed = .{},
        .pending = .{},
        .context = .{
            .iss = iss,
            .sendNext = iss,
            .sendUnack = iss,
        },
        .received = Sorted.init(allocator),
        .allocator = allocator,
        .retransmission = Queue.init(
            allocator,
            sock.tcp.rto * std.time.ns_per_ms,
        ),
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    self.received.deinit();
    self.tcp.removeConnection(self);
    self.retransmission.deinit();
    while (self.pending.pop()) |node| {
        self.allocator.free(node.data.options);
        self.allocator.destroy(node);
    }
    self.state = .CLOSED;
    self.changed.signal();
}

pub fn getMSS(self: *Self) u16 {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.context.mss - @sizeOf(TCP.Header);
}

pub fn usableWindow(self: *Self) u16 {
    return self.context.sendWindow - @as(u16, @truncate(
        self.context.sendNext - self.context.sendUnack,
    ));
}

pub fn retransmit(self: *Self) !void {
    while (self.retransmission.next()) |next| {
        // TODO: make sure data this segment is not on the sendqueue already,
        // before adding it there
        try self.tcp.sendqueue.enqueue(self.id, next);
    }
}

pub fn waitChange(self: *Self, state: State, timeout: isize) !State {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.state != state) return self.state;
    try self.changed.timedWait(&self.mutex, @bitCast(timeout));
    return self.state;
}

pub fn transmit(self: *Self, ack: ?u32, flags: TCP.Flags, data: []const u8) !void {
    // TODO: check usable window
    if (@sizeOf(TCP.Header) + data.len > self.context.mss)
        return error.SegmentTooBig;

    var header = std.mem.zeroInit(TCP.Header, .{
        .seq = nativeToBig(u32, self.context.sendNext),
        .ack = nativeToBig(u32, ack orelse 0),
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

    if (!flags.rst and (!flags.ack or dataLen > 0)) {
        self.retransmission.enqueue(
            self.context.sendNext,
            dataLen,
            buffer,
        ) catch |err| {
            self.allocator.free(buffer);
            return err;
        };
    }

    if (header.flags.syn and dataLen == 0) {
        // after transmiting SYN (or SYN-ACK), we increment SND.NXT by 1
        self.context.sendNext += 1;
    } else {
        // only increment snd.nxt by the amount of data sent
        self.context.sendNext += @truncate(dataLen);
    }

    if (self.state == .SYN_RECEIVED) {
        try self.tcp.ip.send(null, self.id.saddr, .TCP, buffer);
    } else {
        try self.tcp.sendqueue.enqueue(self.id, buffer);
    }
}

pub fn nextPending(self: *Self) ?Incoming {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.pending.popFirst()) |node| {
        defer self.allocator.destroy(node);
        return node.data;
    }
    return null;
}

fn addPending(
    self: *Self,
    ip: *const IPv4.Header,
    seg: *const TCP.Segment,
) !void {
    var next = self.pending.first;
    while (next != null) : (next = next.?.next) {
        if (ip.saddr == next.?.data.id.saddr and
            seg.header.sport == next.?.data.id.sport) return;
    }

    const node = self.allocator.create(
        std.TailQueue(Incoming).Node,
    ) catch return;

    node.data = .{
        .id = .{
            .saddr = ip.saddr,
            .sport = seg.header.sport,
            .daddr = ip.daddr,
            .dport = seg.header.dport,
        },
        .header = seg.header,
        .options = self.allocator.dupe(Option, seg.options) catch {
            self.allocator.destroy(node);
            return;
        },
    };

    self.pending.append(node);

    self.sock.mutex.lock();
    defer self.sock.mutex.unlock();

    self.sock.events.read += 1;
    self.sock.canread.signal();
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

pub fn setActive(
    self: *Self,
    state: State,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
) !void {
    if (self.state != .CLOSED) return error.ConnectionReused;
    self.id = .{
        .sport = sport,
        .saddr = saddr,
        .dport = dport,
        .daddr = daddr,
    };
    self.state = state;
    self.changed.signal();
    self.tcp.addConnection(self) catch {
        self.state = .CLOSED;
        self.changed.signal();
        return;
    };
}

pub fn acceptable(self: Self, segment: *const TCP.Segment) bool {
    const seq = bigToNative(u32, segment.header.seq);
    if (self.context.recvWindow == 0) {
        return segment.data.len == 0 and seq == self.context.recvNext;
    } else if (segment.data.len == 0) {
        return self.context.recvNext <= seq and
            seq < (self.context.recvNext + self.context.recvWindow);
    }

    const dataEnd = seq + segment.data.len - 1;
    const winLimit = self.context.recvNext + self.context.recvWindow;

    return (self.context.recvNext <= seq and seq < winLimit) or
        (self.context.recvNext <= dataEnd and dataEnd < winLimit);
}

// change this name
pub fn unacceptable(self: *Self, segment: *const TCP.Segment) void {
    if (segment.header.flags.rst) return;
    self.transmit(self.context.recvNext, .{ .ack = true }, "") catch {};
}

pub fn acknowledge(self: *Self, seg: *const TCP.Segment, data: []const u8) void {
    const segEnd = bigToNative(u32, seg.header.seq) + if (seg.data.len > 0)
        seg.data.len
    else
        1;

    var seq = self.received.ackable() orelse segEnd;

    if (seq > self.context.recvNext) self.context.recvNext = @truncate(seq);

    // ensure the right ACK sequence for FIN
    if (seg.header.flags.fin and seg.data.len == 0) seq += 1;

    // TODO: choose data from send buffer, instead of receiving from parameter
    self.transmit(@truncate(seq), .{ .ack = true }, data) catch {};
}

pub fn reset(self: *Self, segment: *const TCP.Segment, accepted: bool) void {
    self.transmit(
        bigToNative(u32, segment.header.seq) + 1,
        .{ .rst = true, .ack = accepted },
        "",
    ) catch {};
}

pub fn handleSegment(
    self: *Self,
    ip: *const IPv4.Header,
    segment: *const TCP.Segment,
) void {
    self.mutex.lock();
    defer {
        self.mutex.unlock();
    }

    const isAcceptable = self.acceptable(segment);

    switch (self.state) {
        .LISTEN => {
            if (segment.header.flags.fin or segment.header.flags.rst)
                return;

            if (segment.header.flags.ack) {
                self.reset(segment, true);
            } else if (segment.header.flags.syn) {
                // TODO: check security and precedence

                self.addPending(ip, segment) catch {};
            }
            return;
        },
        .SYN_SENT => {
            if (segment.header.flags.fin) return;
            if (segment.header.flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                if (ack <= self.context.iss or ack > self.context.sendNext) {
                    if (!segment.header.flags.rst)
                        self.transmit(null, .{ .rst = true }, "") catch {};
                    return;
                }
                self.retransmission.ack(ack);
                self.context.sendUnack = ack;
            }
            if (segment.header.flags.rst) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
            // TODO: check security and precedence
            if (segment.header.flags.syn) {
                self.context.irs = bigToNative(u32, segment.header.seq);
                self.context.recvNext = self.context.irs + 1;

                if (self.context.sendUnack > self.context.iss) {
                    self.transmit(
                        self.context.recvNext,
                        .{ .ack = true },
                        "",
                    ) catch return;
                    self.state = .ESTABLISHED;
                    self.changed.signal();
                } else {
                    self.state = .SYN_RECEIVED;
                    self.changed.signal();
                    self.transmit(
                        self.context.recvNext,
                        .{ .ack = true, .syn = true },
                        "",
                    ) catch {};
                }
            }
            return;
        },
        .CLOSED => return,
        else => {}, // other states will be handled next
    }

    if (!isAcceptable) {
        self.unacceptable(segment);
        return;
    }
    if (segment.header.flags.rst or segment.header.flags.syn) {
        self.state = .CLOSED;
        self.changed.signal();
        return;
    }

    // all the following states share the same code above

    switch (self.state) {
        .CLOSING => {
            if (segment.header.flags.rst) {
                self.state = .CLOSED;
                self.changed.signal();
            }
        },
        .SYN_RECEIVED => {
            if (segment.header.flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                if (self.context.sendUnack <= ack and ack <= self.context.sendNext) {
                    self.state = .ESTABLISHED;
                    self.changed.signal();
                } else {
                    self.reset(segment, false);
                    return;
                }
                self.retransmission.ack(ack);
                self.context.sendWinSeq = bigToNative(u32, segment.header.seq);
                self.context.sendWinAck = bigToNative(u32, segment.header.ack);
                self.context.sendWindow = bigToNative(u16, segment.header.window);
                // TODO: allocate send_window ?
                self.state = .ESTABLISHED;
                self.changed.signal();
            }
            return;
        },
        .LAST_ACK => {
            if (segment.header.flags.rst or segment.header.flags.ack) {
                self.state = .CLOSED;
                self.changed.signal();
            }
        },
        .TIME_WAIT => {
            // TODO: check timer to close connection after 2 MSL
            if (segment.header.flags.rst) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }

            if (segment.header.flags.fin) {
                // fin retransmitted
                self.acknowledge(segment, "");
                self.state = .CLOSE_WAIT;
                self.timer.reset();
                self.changed.signal();
            }
        },
        .FIN_WAIT1 => {
            if (segment.header.flags.fin) {
                self.state = .TIME_WAIT;
                self.changed.signal();
                self.timer = std.time.Timer.start() catch unreachable;
            } else if (segment.header.flags.ack) {
                self.state = .FIN_WAIT2;
                self.changed.signal();
            }
        },
        .FIN_WAIT2 => {
            if (segment.header.flags.ack) {
                // "if the retransmission queue is empty, the user's CLOSE can
                // be acknowledged ("ok") but do not delete the TCB."
                if (self.retransmission.items.len == 0) {
                    self.state = .CLOSED;
                    self.changed.signal();
                    return;
                }
            }
            if (segment.header.flags.fin) {
                self.state = .TIME_WAIT;
                self.changed.signal();
                self.timer = std.time.Timer.start() catch unreachable;
            }
        },
        .CLOSE_WAIT => {
            // a FIN has been received...
            return;
        },
        .ESTABLISHED => {
            // TODO: most of the states above also share the code below, so
            // maybe we can move it outisde the switch statement
            if (segment.header.flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                const seq = bigToNative(u32, segment.header.seq);
                if (ack > self.context.sendNext) {
                    // TODO: send ACK
                    std.debug.print("Warning: ACK is bigger than sendNext!\n", .{});
                    self.acknowledge(segment, "");
                    return;
                } else if (ack < self.context.sendUnack) {
                    std.debug.print("Warning: ACK is less than sendUnack!\n", .{});
                } else if (self.context.sendUnack < ack) {
                    self.context.sendUnack = ack;
                    if (ack < self.context.sendNext and
                        (self.context.sendWinSeq < seq or
                        (self.context.sendWinSeq == seq and
                        self.context.sendWinAck <= ack)))
                    {
                        self.context.sendWinSeq = seq;
                        self.context.sendWinAck = ack;
                        self.context.sendWindow = bigToNative(
                            u16,
                            segment.header.window,
                        );
                    }
                }

                self.retransmission.ack(ack);

                if (segment.data.len > 0) {
                    self.received.insert(
                        seq,
                        segment.data,
                        segment.header.flags.psh or
                            segment.header.flags.fin,
                    ) catch return;
                    self.context.recvWindow = @as(
                        u16,
                        @truncate(default_window - self.received.data_len),
                    );
                    self.acknowledge(segment, "");
                }

                if (segment.header.flags.psh or
                    segment.header.flags.fin)
                {
                    self.sock.mutex.lock();
                    defer self.sock.mutex.unlock();
                    self.sock.events.read += 1;
                    self.sock.canread.signal();
                }
            }

            if (segment.header.flags.urg) {
                const urg = bigToNative(u16, segment.header.urgent);
                if (urg > self.context.recvUrgent) {
                    self.context.recvUrgent = urg;
                }
                // TODO: if (self.context.recvUrgent > data consumed ...
            }

            if (segment.header.flags.fin) {
                self.acknowledge(segment, "");
                self.state = .CLOSE_WAIT;
                self.changed.signal();
                if (segment.data.len == 0) self.received.insert(
                    bigToNative(u32, segment.header.seq),
                    "",
                    true,
                ) catch {};
            }
            return;
        },
        // all other states must have been handled previously
        else => unreachable,
    }
}
