const std = @import("std");
const TCP = @import("tcp.zig");
const Connection = @import("conn.zig");

const Self = @This();

const Item = struct {
    id: Connection.Id,
    data: []const u8,
};

tcp: *TCP,
mutex: std.Thread.Mutex,
queue: std.TailQueue(Item),
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, tcp: *TCP) Self {
    return .{
        .tcp = tcp,
        .mutex = .{},
        .queue = .{},
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.queue.pop()) |node| {
        self.allocator.free(node.data.data);
        self.allocator.destroy(node);
    }
}

pub fn enqueue(self: *Self, id: Connection.Id, data: []const u8) !void {
    self.mutex.lock();
    defer self.mutex.unlock();

    // TODO: check if this data is not on the queue already
    // TODO: validate if packet has been ACKed (data has been free'd)

    const node = try self.allocator.create(@TypeOf(self.queue).Node);
    errdefer self.allocator.destroy(node);
    node.data = .{
        .id = id,
        .data = data,
    };
    self.queue.append(node);
    self.tcp.cansend.signal();
}

pub fn empty(self: *Self) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.queue.len == 0;
}

pub fn dequeue(self: *Self) ?Item {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.queue.popFirst()) |node| {
        const data = node.data;
        self.allocator.destroy(node);
        return data;
    }
    return null;
}
