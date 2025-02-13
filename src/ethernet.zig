const std = @import("std");
const Tap = @import("tap.zig");
const native_endian = @import("builtin").target.cpu.arch.endian();

const Self = @This();

pub const BroadcastAddress = [_]u8{0xff} ** 6;

pub const EtherType = enum(u16) {
    ip4 = 0x0800,
    arp = 0x0806,
    ip6 = 0x86DD,
    pub fn fromInt(val: u16) !EtherType {
        return try std.meta.intToEnum(EtherType, val);
    }
};

pub const Header = extern struct {
    dmac: [6]u8 align(1),
    smac: [6]u8 align(1),
    type: u16 align(1),
};

pub const Frame = extern struct {
    header: Header,
    // tags: u32,
    data: [1500]u8 align(1),
};

pub const Handler = struct {
    pub const VTable = struct {
        handle: *const fn (ctx: *anyopaque, frame: *const Frame) void,
    };
    ptr: *anyopaque,
    vtable: *const VTable,
    pub fn handle(self: Handler, frame: *const Frame) void {
        self.vtable.handle(self.ptr, frame);
    }
};

dev: *Tap.Device,
mutex: std.Thread.Mutex,
internal: std.ArrayList(Frame),
handlers: std.AutoHashMap(EtherType, Handler),
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, dev: *Tap.Device) Self {
    return .{
        .dev = dev,
        .mutex = .{},
        .internal = std.ArrayList(Frame).init(allocator),
        .handlers = std.AutoHashMap(EtherType, Handler).init(allocator),
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.handlers.deinit();
}

pub fn addProtocolHandler(self: *Self, protocol: EtherType, handler: Handler) !void {
    try self.handlers.put(protocol, handler);
}

pub fn readFrame(self: *Self) !Frame {
    {
        // internal frames take longer to be processed because the read
        // call blocks on the device fd
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.internal.items.len > 0) {
            return self.internal.pop();
        }
    }
    var buff: [@sizeOf(Frame)]u8 = undefined;
    const size = try self.dev.read(buff[0..]);
    var frame = std.mem.bytesToValue(Frame, buff[0..size]);

    // TODO: maybe not change endianess?
    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &frame.header);
    }
    return frame;
}

pub fn dispatch(self: Self, frame: *const Frame) !void {
    const protocol = try EtherType.fromInt(frame.header.type);
    if (self.handlers.get(protocol)) |*handler| {
        // std.debug.print("Dispatching to handler\n", .{});
        handler.handle(frame);
    } else {
        // std.debug.print("Unsupported protocol: {}\n", .{protocol});
    }
}

pub fn readAndDispatch(self: *Self) !void {
    const frame = try self.readFrame();
    try self.dispatch(&frame);
}

pub fn transmit(self: *Self, data: []const u8, dmac: [6]u8, _type: EtherType) !void {
    var frame: Frame = .{
        .header = .{
            .dmac = undefined,
            .smac = undefined,
            .type = @intFromEnum(_type),
        },
        .data = undefined,
    };
    if (data.len >= frame.data.len) return error.TooMuchData;

    std.mem.copyForwards(u8, frame.data[0..], data);
    std.mem.copyForwards(u8, frame.header.dmac[0..], dmac[0..]);
    std.mem.copyForwards(u8, frame.header.smac[0..], self.dev.hwaddr[0..]);

    if (std.mem.eql(u8, &dmac, &self.dev.hwaddr)) {
        // Handle this internally somehow...
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.internal.append(frame);
        return;
    }

    // TODO: maybe not change endianess?
    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &frame.header);
    }

    _ = try self.dev.write(&std.mem.toBytes(frame));
}
