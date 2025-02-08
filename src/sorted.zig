const std = @import("std");

const Self = @This();

const List = std.DoublyLinkedList(Item);

pub const Item = struct {
    seq: u32, // start of data
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
    _ = self;
    return buffer.len;
}

pub fn getAllData(self: *Self) ![]u8 {
    var node = self.items.first;
    var last: usize = if (node) |f| f.data.seq else return error.NoData;

    var index: usize = 0;
    const buffer = try self.allocator.alloc(u8, self.data_len);

    while (node != null) : (node = node.?.next) {
        const item = node.?.data;
        if (item.seq == last) {
            std.mem.copyForwards(u8, buffer[index..], item.data);
            index += item.data.len;
            last = item.end;
        } else if (item.end > last) {
            const len = item.end - last;
            const data = item.data[item.data.len - len ..];
            std.mem.copyForwards(u8, buffer[index..], data);
            index += data.len;
            last = item.end;
        } else if (item.seq > last) {
            // non-contiguous data
            return error.NonContiguousData;
        }
        if (item.psh) break;
    }

    return if (index < buffer.len)
        self.allocator.realloc(buffer, index)
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
            std.debug.print("Added data\n", .{});
            self.items.insertBefore(item.?, node);
            self.data_len += data.len;
            return;
        }
    }

    self.items.append(node);
    self.data_len += data.len;
    std.debug.print("Added data\n", .{});
}
