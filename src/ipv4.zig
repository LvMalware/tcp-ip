const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const Arp = @import("arp.zig");
const Ethernet = @import("ethernet.zig");

const Self = @This();

const Proto = enum(u8) {
    IP = 0,
    ICMP = 1,
    TCP = 6,
    // ... other protocols
    pub fn fromInt(val: u8) !Proto {
        return try std.meta.intToEnum(Proto, val);
    }
};

const Header = extern struct {
    ver_ihl: u8 align(1),
    tos: u8 align(1),
    len: u16 align(1),
    id: u16 align(1),
    frag: u16 align(1),
    ttl: u8 align(1),
    proto: u8 align(1),
    csum: u16 align(1),
    saddr: u32 align(1),
    daddr: u32 align(1),

    pub fn ihl(self: Header) u8 {
        return switch (native_endian) {
            .big => self.ver_ihl >> 4,
            .little => self.ver_ihl & 0xf,
        };
    }

    pub fn version(self: Header) u8 {
        return switch (native_endian) {
            .little => self.ver_ihl >> 4,
            .big => self.ver_ihl & 0xf,
        };
    }

    pub fn setVersionIHL(self: *Header, ver: u8, hs: u8) void {
        self.ver_ihl = switch (native_endian) {
            .big => (hs << 4) | ver,
            .little => (ver << 4) | hs,
        };
    }

    pub fn checksum(self: Header) u16 {
        var csum: u32 = 0;
        const words = std.mem.bytesAsSlice(u16, std.mem.asBytes(&self));
        for (words) |w| csum += w;
        while (csum >> 16 != 0) {
            csum = (csum & 0xffff) + (csum >> 16);
        }
        return @truncate(~csum);
    }

    pub fn validChecksum(self: Header) bool {
        return self.checksum() == 0;
    }

    pub fn dataOffset(self: Header) usize {
        return @as(usize, self.ihl()) * 4;
    }

    pub fn data(self: *Header, buffer: []const u8) []const u8 {
        return buffer[self.dataOffset()..self.len];
    }
};

pub const Packet = struct {
    header: Header,
    data: []const u8,
};

pub const Handler = struct {
    pub const VTable = struct {
        handle: *const fn (ctx: *anyopaque, packet: *const Packet) void,
    };
    ptr: *anyopaque,
    vtable: *const VTable,
    pub fn handle(self: Handler, packet: *const Packet) void {
        self.vtable.handle(self.ptr, packet);
    }
};

pub const vtable = Ethernet.Handler.VTable{
    .handle = vhandle,
};

arp: *Arp,
ethernet: *Ethernet,
handlers: std.AutoHashMap(Proto, Handler),
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, arp: *Arp, ethernet: *Ethernet) Self {
    return .{
        .arp = arp,
        .ethernet = ethernet,
        .handlers = std.AutoHashMap(Proto, Handler).init(allocator),
        .allocator = allocator,
    };
}

pub fn handler(self: *Self) Ethernet.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

fn vhandle(ctx: *anyopaque, frame: *const Ethernet.Frame) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(frame);
}

pub fn deinit(self: *Self) void {
    self.handlers.deinit();
}

pub fn addProtocolHandler(self: *Self, proto: Proto, h: Handler) !void {
    try self.handlers.put(proto, h);
}

pub fn send(self: *Self, src: ?u32, dst: u32, proto: Proto, data: []const u8) !void {
    var header: Header = .{
        .id = 0,
        .tos = 0,
        .ttl = 64,
        .len = @truncate(@sizeOf(Header) + data.len),
        .csum = 0,
        .frag = 0x4000,
        .saddr = 0,
        .daddr = 0,
        .proto = @intFromEnum(proto),
        .ver_ihl = 0,
    };

    header.setVersionIHL(4, @sizeOf(Header) / 4);

    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &header);
    }

    // both saddr and daddr should be given in network byte-order
    header.saddr = if (src) |addr| addr else self.ethernet.dev.ipaddr;
    header.daddr = dst;

    header.csum = header.checksum();

    const buffer = try self.allocator.alloc(u8, @sizeOf(Header) + data.len);
    defer self.allocator.free(buffer);
    std.mem.copyForwards(u8, buffer, &std.mem.toBytes(header));
    std.mem.copyForwards(u8, buffer[header.dataOffset()..], data);
    const dmac = try self.arp.resolveWait(dst);
    std.debug.print("Sending IP packet to {x}\n", .{dmac});
    try self.ethernet.transmit(buffer, dmac, .ip4);
}

pub fn handle(self: *Self, frame: *const Ethernet.Frame) void {
    var header = std.mem.bytesToValue(Header, frame.data[0..]);
    if (!header.validChecksum()) return;
    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &header);
    }

    const proto = Proto.fromInt(header.proto) catch return;

    const packet = Packet{
        .header = header,
        .data = header.data(&frame.data),
    };

    std.debug.print("[IPv{d}] packet of {d} bytes from {d} to {d}\n", .{
        packet.header.version(),
        packet.header.len,
        packet.header.saddr,
        packet.header.daddr,
    });

    if (self.handlers.get(proto)) |*h| {
        h.handle(&packet);
    }
}
