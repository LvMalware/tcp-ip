const std = @import("std");

const Self = @This();

const List = std.DoublyLinkedList(Item);

pub const Item = struct {
    seq: usize, // start of data
    end: usize, // seq + data.len
    psh: bool,
    data: []const u8,
};

items: List,
data_len: usize,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .items = .{},
        .data_len = 0,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.clear();
}

pub fn clear(self: *Self) void {
    while (self.items.pop()) |last| {
        self.allocator.free(last.data.data);
        self.allocator.destroy(last);
    }
}

pub fn getData(self: *Self, buffer: []u8) !usize {
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
            std.mem.copyForwards(u8, buffer[index..], item.data[0..size]);
            index += size;
            last += size;
            // TODO: add the size to seq and then ensure the whole data has
            // been consumed before removing the segment
        } else if (item.seq > last) {
            // TODO: block until data is contiguous
            return error.NonContiguousData;
        }
        if (item.psh or index == buffer.len) break;
        node = node.?.next;
    }

    // TODO: if buffer is not full and there is no PSH, block until the buffer
    // fills or there is PSH

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

    return index;
}

pub fn getAllData(self: *Self) ![]u8 {
    const buffer = try self.allocator.alloc(u8, self.data_len);

    const size = try self.getData(buffer);

    return if (size < buffer.len)
        self.allocator.realloc(buffer, size)
    else
        buffer;
}

pub fn insert(self: *Self, seq: u32, data: []const u8, psh: bool) !void {
    const node = try self.allocator.create(List.Node);
    errdefer self.allocator.destroy(node);

    node.data = .{
        .seq = seq,
        .end = seq + data.len,
        .psh = psh,
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
                if (prev.data.end >= node.data.end) return;
            }
            self.items.insertBefore(item.?, node);
            self.data_len += data.len;
            return;
        }
    }

    self.items.append(node);
    self.data_len += data.len;
}
