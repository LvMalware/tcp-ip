const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const ARP = @import("arp.zig");
const Ethernet = @import("ethernet.zig");

const Self = @This();

pub const Proto = enum(u8) {
    IP = 0,
    ICMP = 1,
    TCP = 6,
    // ... other protocols
    pub fn fromInt(val: u8) !Proto {
        return try std.meta.intToEnum(Proto, val);
    }
};

pub const VerIHL = switch (native_endian) {
    .big => packed struct {
        ver: u4 = 4,
        ihl: u4 = @truncate(@sizeOf(Header) / 4),
    },
    .little => packed struct {
        ihl: u4 = @truncate(@sizeOf(Header) / 4),
        ver: u4 = 4,
    },
};

pub const Precedence = enum(u3) {
    network_control = 0b111, //Network Control
    internetwork_control = 0b110, //Internetwork Control
    critic = 0b101, // CRITIC/ECP
    flash_override = 0b100, //Flash Override
    flash = 0b011, // Flash
    immediate = 0b010, //Immediate
    priority = 0b001, // Priority
    routine = 0b000, // Routine
};

pub const Header = extern struct {
    ver_ihl: VerIHL align(1),
    tos: u8 align(1),
    len: u16 align(1),
    id: u16 align(1),
    frag: u16 align(1),
    ttl: u8 align(1),
    proto: u8 align(1),
    csum: u16 align(1),
    saddr: u32 align(1),
    daddr: u32 align(1),

    pub fn fromBytes(bytes: []const u8) Header {
        return std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
    }

    pub fn ihl(self: Header) u8 {
        return self.ver_ihl.ihl;
    }

    pub fn version(self: Header) u8 {
        return self.ver_ihl.ver;
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

    pub fn data(self: Header, buffer: []const u8) []const u8 {
        return buffer[self.dataOffset()..std.mem.bigToNative(u16, self.len)];
    }
};

const Id = struct {
    id: u16,
    src: u32,
    dst: u32,
    proto: u8,
    pub fn fromPacket(packet: Packet) Id {
        return .{
            .id = packet.header.id,
            .src = packet.header.saddr,
            .dst = packet.header.daddr,
            .proto = packet.header.proto,
        };
    }
};

pub const Packet = struct {
    header: Header,
    data: []const u8,
    pub fn fromBytes(bytes: []const u8) !Packet {
        // TODO: handle IP options
        const header = Header.fromBytes(bytes);
        if (!header.validChecksum()) return error.InvalidIPChecksum;
        return .{
            .header = header,
            .data = header.data(bytes),
        };
    }

    pub fn dontFragment(self: Packet) bool {
        return self.header.frag & switch (native_endian) {
            .big => 0x4000,
            .little => 0x0040,
        } != 0;
    }

    pub fn moreFragments(self: Packet) bool {
        return self.header.frag & switch (native_endian) {
            .big => 0x2000,
            .little => 0x0020,
        } == 1;
    }

    pub fn fragmentOffset(self: Packet) u13 {
        return switch (native_endian) {
            .big => @truncate(self.header.frag),
            .little => @truncate(std.mem.bigToNative(u16, self.header.frag)),
        };
    }

    pub fn precedence(self: Packet) Precedence {
        return @enumFromInt(self.header.tos >> 5);
    }
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

arp: *ARP,
ethernet: *Ethernet,
handlers: std.AutoHashMap(Proto, Handler),
allocator: std.mem.Allocator,
reassemble: std.AutoHashMap(Id, []u8),

pub fn init(allocator: std.mem.Allocator, arp: *ARP, ethernet: *Ethernet) Self {
    return .{
        .arp = arp,
        .ethernet = ethernet,
        .handlers = std.AutoHashMap(Proto, Handler).init(allocator),
        .allocator = allocator,
        .reassemble = std.AutoHashMap(Id, []u8).init(allocator),
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
    self.reassemble.deinit();
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
        .ver_ihl = .{},
    };

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
    const dmac = try self.arp.resolve(dst, 30 * std.time.ns_per_s);
    try self.ethernet.transmit(buffer, dmac, .ip4);
}

pub fn handle(self: *Self, frame: *const Ethernet.Frame) void {
    const packet = Packet.fromBytes(&frame.data) catch return;
    const proto = Proto.fromInt(packet.header.proto) catch return;

    // std.debug.print("[IPv{d}] packet of {d} bytes from {d} to {d}\n", .{
    //     packet.header.version(),
    //     std.mem.bigToNative(u16, packet.header.len),
    //     packet.header.saddr,
    //     packet.header.daddr,
    // });

    const proto_handler = self.handlers.get(proto) orelse return;

    // TODO: combine packets with same identification, source, destination and protocol (fragmentation reassemble)
    const id = Id.fromPacket(packet);
    if (self.reassemble.get(id)) |data| {
        const needed = packet.fragmentOffset() + packet.data.len;
        if (needed > data.len) {
            self.reassemble.putAssumeCapacity(id, self.allocator.realloc(data, needed) catch return);
        }
        const buffer = self.reassemble.get(id).?;
        std.mem.copyForwards(u8, buffer[packet.fragmentOffset()..], packet.data);
        if (!packet.moreFragments()) {
            proto_handler.handle(&.{
                .header = packet.header,
                .data = buffer,
            });
            _ = self.reassemble.remove(id);
            self.allocator.free(buffer);
        }
    } else if (packet.moreFragments()) {
        self.reassemble.put(id, self.allocator.dupe(u8, packet.data) catch return) catch return;
    } else {
        proto_handler.handle(&packet);
    }
}
