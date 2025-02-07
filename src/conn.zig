const std = @import("std");

const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

const TCP = @import("tcp.zig");
const IPv4 = @import("ipv4.zig");
const Socket = @import("socket.zig");

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
    recvWindow: u16 = default_window,
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
state: State = .CLOSED,
context: Context,
pending: ?std.AutoHashMap(Id, TCP.Segment),
allocator: std.mem.Allocator,
send_buffer: []u8,
receive_buffer: []u8,

pub fn init(self: *Self, allocator: std.mem.Allocator, sock: *Socket) !void {
    const iss = std.crypto.random.int(u32);

    self.* = .{
        .id = undefined,
        .tcp = sock.tcp,
        .sock = sock,
        .pending = null,
        .context = .{
            .iss = iss,
            .sendNext = iss,
            .sendUnack = iss,
        },
        .allocator = allocator,
        .send_buffer = undefined,
        .receive_buffer = try allocator.alloc(u8, default_window),
    };
}

pub fn deinit(self: *Self) void {
    self.tcp.removeConnection(self);
    if (self.pending) |*pending| pending.deinit();
    self.state = .CLOSED;
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
    defer self.allocator.free(buffer);

    std.mem.copyForwards(u8, buffer[0..], std.mem.asBytes(seg));
    std.mem.copyForwards(u8, buffer[seg.dataOffset()..], data);

    try self.tcp.ip.send(null, self.id.saddr, .TCP, buffer);

    self.context.sendNext += if (data.len > 0) @truncate(data.len) else 1;
}

pub fn segmentACK(self: *Self, seg: *const TCP.Segment) TCP.Header {
    defer self.context.sendNext += 1;

    const recvNext = bigToNative(u32, seg.header.seq) + if (seg.data.len == 0)
        1
    else
        seg.data.len;

    if (self.context.recvNext < recvNext) {
        self.context.recvNext = @truncate(recvNext);
    }

    return .{
        .seq = nativeToBig(u32, self.context.sendNext),
        .ack = nativeToBig(u32, @truncate(recvNext)),
        .csum = 0,
        .sport = self.id.dport,
        .dport = self.id.sport,
        .urgent = 0,
        .window = nativeToBig(u16, self.context.recvWindow),
        .rsv_flags = .{
            .rsv = 0,
            .ack = true,
            .rst = false,
            .fin = false,
            .syn = false,
            .psh = false,
            .urg = false,
            .ece = false,
            .cwr = false,
            .doff = @truncate(@sizeOf(TCP.Header) / 4),
        },
    };
}

pub fn setPassive(self: *Self, addr: u32, port: u16) !void {
    if (self.state != .CLOSED) return error.ConnectionReused;
    self.id = .{
        .daddr = addr,
        .dport = port,
    };
    self.state = .LISTEN;
    self.pending = std.AutoHashMap(Id, TCP.Segment).init(self.allocator);
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
    try self.tcp.addConnection(self);
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
    // TODO: handle data that might be present in incoming segments during
    // initial connection (SYN, SYN-ACK, etc.)

    const isAcceptable = self.acceptable(segment);

    switch (self.state) {
        .LISTEN => {
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
                if (self.pending.?.get(id)) |_| return;
                self.pending.?.put(id, segment.*) catch return;
                self.sock.events.read += 1;
            }
        },
        .SYN_SENT => {
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
                self.context.sendUnack = ack;
            }
            if (segment.header.rsv_flags.rst) {
                self.sock.close();
                return;
            }
            // TODO: check security and precedence
            if (segment.header.rsv_flags.syn) {
                self.context.irs = bigToNative(u32, segment.header.seq);
                self.context.recvNext = self.context.irs + 1;

                if (self.context.sendUnack > self.context.iss) {
                    self.state = .ESTABLISHED;
                    var ack: TCP.Header = std.mem.zeroInit(TCP.Header, .{
                        .rsv_flags = .{
                            .doff = @as(u4, @truncate(@sizeOf(TCP.Header) / 4)),
                            .ack = true,
                        },
                        .ack = std.mem.nativeToBig(u32, self.context.recvNext),
                    });
                    self.transmit(&ack, "") catch {};
                } else {
                    self.state = .SYN_RECEIVED;
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
                self.sock.close();
                return;
            }

            if (segment.header.rsv_flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                if (self.context.sendUnack <= ack and ack <= self.context.sendNext) {
                    self.state = .ESTABLISHED;
                } else {
                    self.reset(segment, false);
                    // TODO: maybe drop the connection ?
                }
                std.debug.print("Accepted connection!\n", .{});
                self.context.sendWinSeq = bigToNative(u32, segment.header.seq);
                self.context.sendWinAck = bigToNative(u32, segment.header.ack);
                self.context.sendWindow = bigToNative(u16, segment.header.window);
                // TODO: allocate send_window
                self.state = .ESTABLISHED;
                return;
            }
        },
        .CLOSED => unreachable,
        .CLOSING => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }
        },
        .LAST_ACK => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }

            if (segment.header.rsv_flags.ack) {
                self.sock.close();
                return;
            }
        },
        .TIME_WAIT => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }
        },
        .FIN_WAIT1 => {
            // TODO: maybe process along with established?
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }

            if (segment.header.rsv_flags.ack) {
                self.state = .FIN_WAIT2;
            }
        },
        .FIN_WAIT2 => {
            // TODO: maybe process along with established?
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }
            if (segment.header.rsv_flags.ack) {
                // "if the retransmission queue is empty, the user's CLOSE can
                // be acknowledged ("ok") but do not delete the TCB."
            }
        },
        .CLOSE_WAIT, .ESTABLISHED => {
            if (!isAcceptable) {
                self.unacceptable(segment);
                return;
            }
            if (segment.header.rsv_flags.rst or segment.header.rsv_flags.syn) {
                self.sock.close();
                return;
            }

            if (segment.header.rsv_flags.ack) {
                const ack = bigToNative(u32, segment.header.ack);
                const seq = bigToNative(u32, segment.header.seq);
                if (ack > self.context.sendNext) {
                    // TODO: send ACK
                    return;
                } else if (ack < self.context.sendUnack) {
                    return;
                } else if (self.context.sendUnack < ack) {
                    self.context.sendUnack = ack;
                    // TODO: remove acked segments from retransmission queue
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
                // TODO: handle data
            }

            if (segment.header.rsv_flags.urg) {
                const urg = bigToNative(u16, segment.header.urgent);
                if (urg > self.context.recvUrgent) {
                    self.context.recvUrgent = urg;
                }
                // TODO: if (self.context.recvUrgent > data consumed ...
            }
        },
    }

    if (segment.header.rsv_flags.ack) {
        // TODO
        switch (self.state) {
            .ESTABLISHED => {
                std.debug.print("Flags: {}\n", .{segment.header.rsv_flags});
                if (!self.acceptable(segment)) {
                    std.debug.print("Unacceptable segment!\n", .{});
                    return;
                }
                const seq = bigToNative(u32, segment.header.seq);
                if (seq >= self.context.sendUnack) self.context.sendUnack = seq;
                if (segment.header.rsv_flags.fin) {
                    std.debug.print("FIN on established connection!\n", .{});
                    var ack = self.segmentACK(segment);
                    ack.csum = ack.checksum(
                        self.id.saddr,
                        self.id.daddr,
                        @intFromEnum(IPv4.Proto.TCP),
                        "",
                    );
                    self.tcp.ip.send(null, self.id.saddr, .TCP, std.mem.asBytes(&ack)) catch return;
                    self.state = .CLOSE_WAIT;
                    return;
                }

                if (segment.header.rsv_flags.rst) {
                    // TODO: RST on established connection
                    return;
                }

                std.debug.print("Received data: {s}\n", .{segment.data});

                var ack = self.segmentACK(segment);
                ack.csum = ack.checksum(
                    self.id.saddr,
                    self.id.daddr,
                    @intFromEnum(IPv4.Proto.TCP),
                    segment.data,
                );
                const buffer = self.allocator.alloc(u8, @sizeOf(TCP.Header) + segment.data.len) catch return;
                defer self.allocator.free(buffer);
                std.mem.copyForwards(u8, buffer, std.mem.asBytes(&ack));
                std.mem.copyForwards(u8, buffer[@sizeOf(TCP.Header)..], segment.data);
                self.tcp.ip.send(null, self.id.saddr, .TCP, std.mem.asBytes(&ack)) catch return;
            },
            else => {
                // TODO
            },
        }
    } else if (segment.header.rsv_flags.fin) {
        std.debug.print("Fin right away?\n", .{});
    }
}
