const std = @import("std");
const Connection = @import("conn.zig");

const Self = @This();

pub const Item = struct {
    conn: Connection.Id,
    segend: u32,
    rtcount: usize,
    timeout: usize,
    segment: []const u8,
};

fn compare(context: bool, a: Item, b: Item) std.math.Order {
    _ = context;
    return std.math.order(a.timeout, b.timeout);
}

const Queue = std.PriorityQueue(Item, bool, compare);

rto: usize, // retransmission timeout
done: std.atomic.Value(bool),
queue: Queue,
timer: std.time.Timer,
mutex: std.Thread.Mutex,
semaphore: std.Thread.Semaphore,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, rto: usize) !Self {
    return .{
        .rto = rto,
        .done = std.atomic.Value(bool).init(false),
        .queue = Queue.init(allocator, true),
        .timer = try std.time.Timer.start(),
        .mutex = .{},
        .semaphore = .{},
        .allocator = allocator,
    };
}

pub fn enqueue(self: *Self, segment: []const u8, id: Connection.Id, end: u32) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    try self.queue.add(.{
        .conn = id,
        .segend = end,
        .rtcount = 0,
        .timeout = self.timer.read(),
        .segment = segment,
    });
    self.semaphore.post();
}

pub fn deinit(self: *Self) void {
    self.done.store(true, .release);
    self.semaphore.post();

    self.mutex.lock();
    defer self.mutex.unlock();

    while (self.queue.removeOrNull()) |item| {
        self.allocator.free(item.segment);
    }
}

fn checkPending(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var iterator = self.queue.iterator();
    while (iterator.next()) |next| {
        if (next.timeout <= self.timer.read()) {
            self.semaphore.post();
        } else break;
    }
}

pub fn dequeue(self: *Self) ?Item {
    while (!self.done.load(.acquire)) {
        self.semaphore.timedWait(self.rto) catch {
            self.checkPending();
            continue;
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        var next = self.queue.removeOrNull() orelse continue;
        next.rtcount += 1;
        next.timeout = self.timer.read() + next.rtcount * self.rto;
        self.queue.add(next) catch {};
        return next;
    }
    return null;
}

pub fn ack(self: *Self, id: Connection.Id, seq: u32) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    var index: usize = 0;
    while (index < self.queue.count()) {
        if (self.queue.items[index].conn.eql(id) and self.queue.items[index].segend <= seq) {
            const item = self.queue.removeIndex(index);
            self.allocator.free(item.segment);
            continue;
        }
        index += 1;
    }
}

pub fn removeAll(self: *Self, id: Connection.Id) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    var index: usize = 0;
    while (index < self.queue.count()) {
        if (self.queue.items[index].conn.eql(id)) {
            const item = self.queue.removeIndex(index);
            self.allocator.free(item.segment);
            continue;
        }
        index += 1;
    }
}

// TODO: change sendqueue to make unecessary counting the pending segments
pub fn countPending(self: *Self, id: Connection.Id) usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    var count: usize = 0;

    var iter = self.queue.iterator();
    while (iter.next()) |item| {
        if (item.conn.eql(id)) count += 1;
    }

    return count;
}
