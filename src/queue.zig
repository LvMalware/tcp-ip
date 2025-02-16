const std = @import("std");

const TCP = @import("tcp.zig");

const Self = @This();

const Segment = struct {
    seq: u32,
    len: usize,
    data: []const u8,
    delay: usize,
    timer: std.time.Timer,
};

rto: usize,
items: std.TailQueue(Segment),
mutex: std.Thread.Mutex,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, rtt: usize) Self {
    return .{
        .rto = (rtt + 100) * std.time.ns_per_ms,
        .items = .{},
        .mutex = .{},
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.items.pop()) |node| {
        self.allocator.free(node.data.data);
        self.allocator.destroy(node);
    }
}

pub fn enqueue(self: *Self, seq: u32, len: usize, data: []const u8) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    const node = try self.allocator.create(std.TailQueue(Segment).Node);
    node.data = .{
        .seq = seq,
        .len = len,
        .data = data,
        .delay = self.rto,
        .timer = try std.time.Timer.start(),
    };

    self.items.append(node);
}

pub fn ack(self: *Self, seq: u32) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var node = self.items.first;
    while (node != null) {
        const nxt = node.?.next;
        const seg = node.?.data.seq + node.?.data.len;
        if (seg <= seq) {
            self.items.remove(node.?);
            self.allocator.free(node.?.data.data);
            self.allocator.destroy(node.?);
        }
        node = nxt;
    }
}

pub fn next(self: *Self) ?[]const u8 {
    self.mutex.lock();
    defer self.mutex.unlock();
    var node = self.items.first;
    while (node != null) : (node = node.?.next) {
        if (node.?.data.timer.read() >= node.?.data.delay) {
            if (node.?.data.delay < 8 * self.rto) {
                node.?.data.delay += self.rto;
            }
            defer node.?.data.timer.reset();
            self.items.remove(node.?);
            self.items.append(node.?);
            return node.?.data.data;
        }
    }
    return null;
}
