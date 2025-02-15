const std = @import("std");

const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Queue = @import("queue.zig");
const Socket = @import("socket.zig");
const Sorted = @import("sorted.zig");

const Self = @This();

const default_window = 64256;

pub const Id = struct {
    saddr: u32 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    dport: u16 = 0,
};

const Context = struct {
    irs: u32 = 0,
    iss: u32 = 0,
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

const Incoming = struct {
    id: Id,
    header: TCP.Header,
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
backlog: usize,
changed: std.Thread.Condition,
context: Context,
pending: std.TailQueue(Incoming),
received: Sorted,
allocator: std.mem.Allocator,
// send_buffer: []u8,
retransmission: Queue,
// TODO: have a thread to retransmit packets...

pub fn init(self: *Self, allocator: std.mem.Allocator, sock: *Socket) void {
    const iss = std.crypto.random.int(u32);

    self.* = .{
        .id = undefined,
        .tcp = sock.tcp,
        .sock = sock,
        .mutex = .{},
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
        // .send_buffer = undefined,
        .retransmission = Queue.init(allocator, 400 * std.time.ns_per_ms),
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    self.received.deinit();
    self.retransmission.deinit();
    self.tcp.removeConnection(self);
    while (self.pending.pop()) |node| {
        self.allocator.destroy(node);
    }
    self.state = .CLOSED;
    self.changed.signal();
}

pub fn retransmit(self: *Self) !void {
    if (self.retransmission.next()) |next| {
        try self.tcp.ip.send(null, self.id.saddr, .TCP, next);
    }
}

pub fn transmit(self: *Self, seg: *TCP.Header, data: []const u8) !void {
    seg.csum = 0;
    seg.seq = nativeToBig(u32, self.context.sendNext);
    seg.sport = self.id.dport;
    seg.dport = self.id.sport;
    seg.window = nativeToBig(u16, self.context.recvWindow);

    seg.csum = seg.checksum(
        self.id.daddr,
        self.id.saddr,
        @intFromEnum(IPv4.Proto.TCP),
        data,
    );

    const buffer = try self.allocator.alloc(u8, @sizeOf(TCP.Header) + data.len);
    self.retransmission.enqueue(self.context.sendNext, data.len, buffer) catch {};

    std.mem.copyForwards(u8, buffer[0..], std.mem.asBytes(seg));
    std.mem.copyForwards(u8, buffer[seg.dataOffset()..], data);

    try self.tcp.ip.send(null, self.id.saddr, .TCP, buffer);

    // only increment snd.nxt by the amount of data sent
    self.context.sendNext += @truncate(data.len);
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

fn hasPending(self: *Self, id: Id) bool {
    var next = self.pending.first;
    while (next != null) : (next = next.?.next) {
        if (id.saddr == next.?.data.id.saddr and id.sport == next.?.data.id.sport) return true;
    }
    return false;
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
    if (segment.header.rsv_flags.rst) return;
    var ack = std.mem.zeroInit(TCP.Header, .{
        .ack = nativeToBig(u32, self.context.recvNext),
        .rsv_flags = .{
            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
            .ack = true,
        },
    });
    self.transmit(&ack, "") catch {};
}

pub fn acknowledge(self: *Self, seg: *const TCP.Segment, data: []const u8) void {
    const seq = bigToNative(u32, seg.header.seq) + if (seg.data.len > 0)
        seg.data.len
    else
        1;
    if (seq > self.context.recvNext) self.context.recvNext = @truncate(seq);
    var ack = std.mem.zeroInit(TCP.Header, .{
        .ack = nativeToBig(u32, @truncate(seq)),
        .rsv_flags = .{
            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
            .ack = true,
        },
    });
    // TODO: choose data from send buffer, instead of receiving it as a parameter
    self.transmit(&ack, data) catch {};
}

pub fn reset(self: *Self, segment: *const TCP.Segment, accepted: bool) void {
    var rst: TCP.Header = std.mem.zeroInit(TCP.Header, .{
        .seq = if (segment.header.rsv_flags.ack) segment.header.ack else 0,
        .ack = nativeToBig(u32, bigToNative(u32, segment.header.seq) + 1),
        .rsv_flags = .{
            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
            .rst = true,
            .ack = accepted,
        },
    });
    self.transmit(&rst, "") catch {};
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

    // std.debug.print("State: {}\n", .{self.state});
    const isAcceptable = self.acceptable(segment);

    switch (self.state) {
        .LISTEN => {
            if (segment.header.rsv_flags.fin) return;
            if (segment.header.rsv_flags.rst) {
                return;
            } else if (segment.header.rsv_flags.ack) {
                var rst = TCP.segmentRST(&segment.header);
                rst.csum = rst.checksum(
                    ip.saddr,
                    ip.daddr,
                    ip.proto,
                    "",
                );
                self.tcp.ip.send(
                    null,
                    ip.saddr,
                    .TCP,
                    std.mem.asBytes(&rst),
                ) catch {};
            } else if (segment.header.rsv_flags.syn) {
                // TODO: check security and precedence
                const id = Id{
                    .saddr = ip.saddr,
                    .sport = segment.header.sport,
                    .daddr = ip.daddr,
                    .dport = segment.header.dport,
                };

                if (self.hasPending(id) or self.pending.len == self.backlog) {
                    return;
                }

                const node = self.allocator.create(
                    std.TailQueue(Incoming).Node,
                ) catch return;
                node.data = .{
                    .id = id,
                    .header = segment.header,
                };

                self.pending.append(node);
                self.sock.mutex.lock();
                defer self.sock.mutex.unlock();
                self.sock.events.read += 1;
                self.sock.canread.signal();
                return;
            }
        },
        .SYN_SENT => {
            if (segment.header.rsv_flags.fin) return;
            if (segment.header.rsv_flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                if (ack <= self.context.iss or ack > self.context.sendNext) {
                    if (segment.header.rsv_flags.rst) return;

                    var rst: TCP.Header = std.mem.zeroInit(TCP.Header, .{
                        .seq = segment.header.ack,
                        .rsv_flags = .{
                            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                            .rst = true,
                        },
                    });
                    self.transmit(&rst, "") catch {};
                    return;
                }
                self.retransmission.ack(ack);
                self.context.sendUnack = ack;
            }
            if (segment.header.rsv_flags.rst) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
            // TODO: check security and precedence
            if (segment.header.rsv_flags.syn) {
                self.context.irs = bigToNative(u32, segment.header.seq);
                self.context.recvNext = self.context.irs + 1;

                if (self.context.sendUnack > self.context.iss) {
                    var ack: TCP.Header = std.mem.zeroInit(TCP.Header, .{
                        .rsv_flags = .{
                            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                            .ack = true,
                        },
                        .ack = std.mem.nativeToBig(u32, self.context.recvNext),
                    });
                    self.transmit(&ack, "") catch {};
                    self.state = .ESTABLISHED;
                    self.changed.signal();
                } else {
                    self.state = .SYN_RECEIVED;
                    self.changed.signal();
                    var ack: TCP.Header = std.mem.zeroInit(TCP.Header, .{
                        .rsv_flags = .{
                            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                            .ack = true,
                            .syn = true,
                        },
                        .ack = std.mem.nativeToBig(u32, self.context.recvNext),
                    });
                    self.transmit(&ack, "") catch {};
                }
            }
        },
        .SYN_RECEIVED => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }

            if (segment.header.rsv_flags.ack) {
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
                // TODO: allocate send_window
                self.state = .ESTABLISHED;
                self.changed.signal();
                return;
            }
        },
        .CLOSED => return,
        .CLOSING => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
        },
        .LAST_ACK => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }

            if (segment.header.rsv_flags.ack) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
        },
        .TIME_WAIT => {
            // TODO: start a timer to close the connection
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
        },
        .FIN_WAIT1 => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }

            if (segment.header.rsv_flags.fin) {
                self.state = .TIME_WAIT;
                self.changed.signal();
            } else if (segment.header.rsv_flags.ack) {
                self.state = .FIN_WAIT2;
                self.changed.signal();
            }
        },
        .FIN_WAIT2 => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
            if (segment.header.rsv_flags.ack) {
                // "if the retransmission queue is empty, the user's CLOSE can
                // be acknowledged ("ok") but do not delete the TCB."
            }
            if (segment.header.rsv_flags.fin) {
                self.state = .TIME_WAIT;
                self.changed.signal();
            }
        },
        .CLOSE_WAIT => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }
            // TODO: start a timer to finish connection
        },
        .ESTABLISHED => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.state = .CLOSED;
                self.changed.signal();
                return;
            }

            if (segment.header.rsv_flags.ack) {
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
                        segment.header.rsv_flags.psh or
                            segment.header.rsv_flags.fin,
                    ) catch return;
                    self.context.recvWindow = @as(
                        u16,
                        @truncate(default_window - self.received.data_len),
                    );
                    self.acknowledge(segment, "");
                }

                if (segment.header.rsv_flags.psh or
                    segment.header.rsv_flags.fin)
                {
                    self.sock.mutex.lock();
                    defer self.sock.mutex.unlock();
                    self.sock.events.read += 1;
                    self.sock.canread.signal();
                }
            }

            if (segment.header.rsv_flags.urg) {
                const urg = bigToNative(u16, segment.header.urgent);
                if (urg > self.context.recvUrgent) {
                    self.context.recvUrgent = urg;
                }
                // TODO: if (self.context.recvUrgent > data consumed ...
            }

            if (segment.header.rsv_flags.fin) {
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
    }
}
