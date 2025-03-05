const std = @import("std");
const Connection = @import("conn.zig");

const Self = @This();
const Node = std.TailQueue(Item).Node;

const Item = struct {
    id: Connection.Id,
    end: u32,
    ret: usize = 0,
    timeout: usize,
    segment: []const u8,
};

rto: usize,
timer: std.time.Timer,
mutex: std.Thread.Mutex,
queue: std.TailQueue(Item),
pending: std.Thread.Condition,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, rto: usize) Self {
    return .{
        .rto = rto,
        .timer = std.time.Timer.start() catch unreachable,
        .mutex = .{},
        .queue = .{},
        .pending = .{},
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.queue.popFirst()) |item| {
        self.allocator.free(item.data.segment);
        self.allocator.destroy(item);
    }
    self.pending.signal();
}

pub fn insert(self: *Self, node: *Node) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var item = self.queue.first;
    while (item != null) : (item = item.?.next) {
        if (item.?.data.timeout > node.data.timeout) {
            self.queue.insertBefore(item.?, node);
            return;
        }
    }
    self.queue.append(node);
    // signal pending so dequeue() will unlock when queue is currently empty
    self.pending.signal();
}

pub fn dequeue(self: *Self) ?Item {
    self.mutex.lock();
    defer self.mutex.unlock();

    while (self.queue.first == null) {
        self.pending.wait(&self.mutex);
    }

    while (self.queue.first.?.data.timeout > self.timer.read()) {
        self.pending.timedWait(
            &self.mutex,
            self.queue.first.?.data.timeout - self.timer.read(),
        ) catch {};
        if (self.queue.first == null) return null;
    }

    if (self.queue.popFirst()) |node| {
        node.data.ret += 1;
        node.data.timeout += node.data.ret * self.rto * std.time.ns_per_ms;
        self.queue.append(node);

        // TODO: if node.data.ret > some limit, discard packet / reset connection

        return node.data;
    }
    return null;
}

pub fn enqueue(
    self: *Self,
    segment: []const u8,
    id: Connection.Id,
    end: u32,
) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    const node = try self.allocator.create(Node);
    node.data = .{
        .id = id,
        .end = end,
        .timeout = self.timer.read(),
        .segment = segment,
    };
    if (self.queue.first) |first| {
        self.queue.insertBefore(first, node);
    } else {
        self.queue.append(node);
    }
    self.pending.signal();
}

pub fn ack(self: *Self, id: Connection.Id, seq: u32) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    const count = self.queue.len;
    var item = self.queue.first;
    while (item != null) {
        const next = item.?.next;
        if (item.?.data.id.eql(id) and item.?.data.end <= seq) {
            self.queue.remove(item.?);
            self.allocator.free(item.?.data.segment);
            self.allocator.destroy(item.?);
        }
        item = next;
    }
    // signal pending to avoid dequeue() waiting to retransmit ACKed segments
    if (count > self.queue.len) self.pending.signal();
}

pub fn countPending(self: *Self, id: Connection.Id) usize {
    self.mutex.lock();
    defer self.mutex.unlock();

    var count: usize = 0;

    var item = self.queue.first;
    while (item != null) : (item = item.?.next) {
        if (item.?.data.id.eql(id)) count += 1;
    }
    return count;
}
