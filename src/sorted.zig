const std = @import("std");

const Self = @This();

const List = std.DoublyLinkedList(Item);

pub const Item = struct {
    seq: usize, // start of data
    end: usize, // seq + data.len
    psh: bool,
    con: bool,
    data: []const u8,
};

psh: usize,
items: List,
mutex: std.Thread.Mutex,
data_len: usize,
condition: std.Thread.Condition,
allocator: std.mem.Allocator,
last_cont: ?usize,
contiguous_len: usize,

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .psh = 0,
        .items = .{},
        .mutex = .{},
        .data_len = 0,
        .allocator = allocator,
        .last_cont = null,
        .condition = .{},
        .contiguous_len = 0,
    };
}

pub fn deinit(self: *Self) void {
    self.psh += 1;
    self.condition.signal();
    self.clear();
}

pub fn clear(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.items.pop()) |last| {
        self.allocator.free(last.data.data);
        self.allocator.destroy(last);
    }
}

pub fn getData(self: *Self, buffer: []u8) !usize {
    self.mutex.lock();
    defer self.mutex.unlock();

    while (self.contiguous_len < buffer.len and self.psh == 0) {
        self.condition.wait(&self.mutex);
    }
    var node = self.items.first;
    var last: usize = if (node) |f| f.data.seq else return error.NoData;
    var index: usize = 0;

    while (node != null) {
        const item = node.?.data;
        const avail = buffer.len - index;
        if (item.seq >= last) {
            const diff = item.end - last;
            const data = item.data[item.data.len - diff ..];
            const size = if (avail > data.len) data.len else avail;
            std.mem.copyForwards(u8, buffer[index..], data[0..size]);
            index += size;
            last += size;
            node.?.data.seq += size;
        } else if (item.seq > last) {
            return error.NonContiguousData;
        }
        if (item.psh) {
            self.psh -= if (self.psh > 0) 1 else 0;
            break;
        }
        if (index == buffer.len) break;
        node = node.?.next;
    }

    var item = self.items.first;
    while (item != null and item != node) {
        const next = item.?.next;
        self.items.remove(item.?);
        self.allocator.free(item.?.data.data);
        self.allocator.destroy(item.?);
        item = next;
    }

    if (node != null and last >= node.?.data.end) {
        self.items.remove(node.?);
        self.allocator.free(node.?.data.data);
        self.allocator.destroy(node.?);
    }

    self.data_len -= index;
    self.contiguous_len -= index;

    return index;
}

pub fn getAllData(self: *Self) ![]u8 {
    const buffer = try self.allocator.alloc(u8, self.contiguous_len);

    const size = try self.getData(buffer);

    return if (size < buffer.len)
        self.allocator.realloc(buffer, size)
    else
        buffer;
}

fn checkContiguous(self: *Self, node: *List.Node) void {
    if (node.prev) |prev| {
        node.data.con = prev.data.con and prev.data.end >= node.data.seq;
        if (node.data.con) {
            self.contiguous_len += node.data.end - prev.data.end;
        } else return;
    } else {
        node.data.con = if (self.last_cont) |last|
            last >= node.data.seq
        else
            true;
        if (!node.data.con) return;
        self.contiguous_len += node.data.data.len;
    }

    self.last_cont = node.data.end;

    if (node.data.psh) self.psh += 1;

    var next = node.next;
    while (next != null) : (next = next.?.next) {
        next.?.data.con = next.?.prev.?.data.end >= next.?.data.seq;
        if (!next.?.data.con) break;
        self.contiguous_len += next.?.data.end - next.?.prev.?.data.end;
        self.last_cont = next.?.data.end;
        if (next.?.data.psh) self.psh += 1;
    }
}

pub fn insert(self: *Self, seq: usize, data: []const u8, psh: bool) !void {
    self.mutex.lock();
    defer self.mutex.unlock();

    defer {
        self.condition.signal();
    }

    const node = try self.allocator.create(List.Node);
    errdefer self.allocator.destroy(node);

    node.data = .{
        .seq = seq,
        .end = seq + data.len,
        .psh = psh,
        .con = false,
        .data = try self.allocator.dupe(u8, data),
    };

    var item = self.items.first;

    // TODO: check data boundaries when inserting to skip previously received
    // data

    while (item != null) : (item = item.?.next) {
        if (item.?.data.seq <= seq and item.?.data.end >= node.data.end)
            return;

        if (item.?.data.seq > seq) {
            if (item.?.prev) |prev| {
                if (prev.data.end >= node.data.end) {
                    self.allocator.free(node.data.data);
                    self.allocator.destroy(node);
                    return;
                }
            }
            self.items.insertBefore(item.?, node);
            self.data_len += data.len;
            self.checkContiguous(node);
            return;
        }
    }

    self.items.append(node);
    self.data_len += data.len;
    self.checkContiguous(node);
}
