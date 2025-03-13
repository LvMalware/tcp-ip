const std = @import("std");
const Connection = @import("conn.zig");

const Self = @This();
const Node = std.DoublyLinkedList(Item).Node;

const Item = struct {
    id: Connection.Id,
    end: u32,
    ret: usize = 0,
    timeout: usize,
    segment: []const u8,
};

fn compare(context: bool, a: Item, b: Item) std.math.Order {
    _ = .{context}; // unused context
    return std.math.order(a.timeout, b.timeout);
}

const Queue = std.PriorityQueue(Item, bool, compare);

rto: usize,
timer: std.time.Timer,
mutex: std.Thread.Mutex,
queue: Queue,
pending: std.Thread.Condition,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, rto: usize) Self {
    return .{
        .rto = rto,
        .timer = std.time.Timer.start() catch unreachable,
        .mutex = .{},
        .queue = Queue.init(allocator, true),
        .pending = .{},
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.queue.removeOrNull()) |item| {
        self.allocator.free(item.segment);
    }
    self.queue.deinit();
    self.pending.signal();
}

pub fn dequeue(self: *Self) ?Item {
    self.mutex.lock();
    defer self.mutex.unlock();

    while (self.queue.peek() == null) {
        self.pending.wait(&self.mutex);
    }

    var diff = @subWithOverflow(self.queue.peek().?.timeout, self.timer.read());
    while (diff[1] == 0 and diff[0] != 0) {
        self.pending.timedWait(&self.mutex, diff[0]) catch {};
        if (self.queue.peek() == null) return null;
        diff = @subWithOverflow(self.queue.peek().?.timeout, self.timer.read());
    }

    var next = self.queue.remove();
    next.ret += 1;
    next.timeout = self.timer.read() + next.ret * self.rto * std.time.ns_per_ms;
    self.queue.add(next) catch {};
    return next;
}

pub fn enqueue(
    self: *Self,
    segment: []const u8,
    id: Connection.Id,
    end: u32,
) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    try self.queue.add(.{
        .id = id,
        .end = end,
        .timeout = self.timer.read(),
        .segment = segment,
    });
    self.pending.signal();
}

pub fn ack(self: *Self, id: Connection.Id, seq: u32) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    const count = self.queue.count();
    var index: usize = 0;
    while (index < self.queue.count()) {
        if (self.queue.items[index].id.eql(id) and
            self.queue.items[index].end <= seq)
        {
            const item = self.queue.removeIndex(index);
            self.allocator.free(item.segment);
            continue;
        }
        index += 1;
    }
    // signal pending to avoid dequeue() waiting to retransmit ACKed segments
    if (count > self.queue.count()) self.pending.signal();
}

pub fn removeAll(self: *Self, id: Connection.Id) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var index: usize = 0;
    const count = self.queue.count();
    while (index < self.queue.count()) {
        if (self.queue.items[index].id.eql(id)) {
            const item = self.queue.removeIndex(index);
            self.allocator.free(item.segment);
            continue;
        }
        index += 1;
    }
    if (count > self.queue.count()) self.pending.signal();
}

pub fn countPending(self: *Self, id: Connection.Id) usize {
    self.mutex.lock();
    defer self.mutex.unlock();

    var count: usize = 0;

    var iter = self.queue.iterator();
    while (iter.next()) |item| {
        if (item.id.eql(id)) count += 1;
    }
    return count;
}
