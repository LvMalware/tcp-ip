const std = @import("std");
const Utils = @import("utils.zig");
const Ethernet = @import("ethernet.zig");
const native_endian = @import("builtin").target.cpu.arch.endian();

const Self = @This();

const CacheState = enum(u8) {
    free,
    waiting,
    resolved,
};

const Cached = struct {
    hwtype: HWType,
    smac: [6]u8,
    saddr: u32,
    state: CacheState = .free,
    resolved: std.Thread.Condition,
};

const Opcode = enum(u16) {
    arp_request = 0x0001,
    arp_reply = 0x0002,
    rarp_request = 0x003,
    rarp_reply = 0x004,
    pub fn fromInt(val: u16) !Opcode {
        return try std.meta.intToEnum(Opcode, val);
    }
};

const HWType = enum(u16) {
    Ethernet = 0x0001,
    pub fn fromInt(val: u16) !HWType {
        return try std.meta.intToEnum(HWType, val);
    }
};

const Proto = enum(u16) {
    IPV4 = 0x0800,
    pub fn fromInt(val: u16) !Proto {
        return try std.meta.intToEnum(Proto, val);
    }
};

const Header = extern struct {
    hwtype: u16 align(1),
    proto: u16 align(1),
    hwsize: u8 align(1),
    prosize: u8 align(1),
    opcode: u16 align(1),
};

const ARPIPv4 = extern struct {
    smac: [6]u8 align(1),
    saddr: u32 align(1),
    dmac: [6]u8 align(1),
    daddr: u32 align(1),
};

pub const vtable = Ethernet.Handler.VTable{
    .handle = vhandle,
};

mutex: std.Thread.Mutex,
cache: std.ArrayList(Cached),
ethernet: *Ethernet,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, eth: *Ethernet) Self {
    return .{
        .mutex = .{},
        .cache = std.ArrayList(Cached).init(allocator),
        .ethernet = eth,
        .allocator = allocator,
    };
}

pub fn deinit(self: Self) void {
    _ = .{self};
}

fn vhandle(ctx: *anyopaque, frame: *const Ethernet.Frame) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(frame);
}

pub fn handler(self: *Self) Ethernet.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

fn merge(self: *Self, packet: *const Header, arp: *const ARPIPv4) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    const hwtype = HWType.fromInt(packet.hwtype) catch unreachable;
    for (self.cache.items) |*cached| {
        if (cached.hwtype == hwtype and arp.saddr == cached.saddr) {
            std.mem.copyForwards(u8, cached.smac[0..], arp.smac[0..]);
            return true;
        }
    }
    return false;
}

pub fn insertEntry(self: *Self, packet: *const Header, arp: *const ARPIPv4) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    var entry: Cached = .{
        .smac = undefined,
        .state = .resolved,
        .saddr = arp.saddr,
        .hwtype = HWType.fromInt(packet.hwtype) catch unreachable,
        .resolved = .{},
    };
    std.mem.copyForwards(u8, entry.smac[0..], arp.smac[0..]);
    self.cache.append(entry) catch return;
}

pub fn request(self: Self, addr: u32) !void {
    var header: Header = .{
        .hwtype = @intFromEnum(HWType.Ethernet),
        .proto = @intFromEnum(Proto.IPV4),
        .hwsize = 6,
        .prosize = 4,
        .opcode = @intFromEnum(Opcode.arp_request),
    };

    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &header);
    }

    const ipv4: ARPIPv4 = .{
        .smac = self.ethernet.dev.hwaddr,
        .saddr = self.ethernet.dev.ipaddr,
        .dmac = std.mem.zeroes([6]u8),
        .daddr = addr,
    };

    std.debug.print("[ARP] Who has {s}? Tell {s}\n", .{
        Utils.ntop(ipv4.daddr),
        Utils.ntop(ipv4.saddr),
    });

    const buffer = try self.allocator.alloc(u8, @sizeOf(Header) + @sizeOf(ARPIPv4));
    defer self.allocator.free(buffer);

    std.mem.copyForwards(u8, buffer[0..], &std.mem.toBytes(header));
    std.mem.copyForwards(u8, buffer[@sizeOf(Header)..], &std.mem.toBytes(ipv4));

    try self.ethernet.transmit(buffer, Ethernet.BroadcastAddress, .arp);
}

pub fn resolve(self: *Self, addr: u32, timeout: isize) ![6]u8 {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (addr == self.ethernet.dev.ipaddr) return self.ethernet.dev.hwaddr;
    for (self.cache.items) |*i| {
        if (i.saddr != addr) {
            continue;
        } else if (i.state == .waiting) {
            try i.resolved.timedWait(&self.mutex, @bitCast(timeout));
            return i.smac;
        } else {
            return i.smac;
        }
    }

    try self.cache.append(.{
        .smac = undefined,
        .saddr = addr,
        .state = .waiting,
        .hwtype = .Ethernet,
        .resolved = .{},
    });
    try self.request(addr);
    const entry = &self.cache.items[self.cache.items.len - 1];
    try entry.resolved.timedWait(&self.mutex, @bitCast(timeout));
    return entry.smac;
}

pub fn reply(self: Self, packet: *const Header, arp: *const ARPIPv4) !void {
    var header: Header = .{
        .hwtype = packet.hwtype,
        .proto = packet.proto,
        .hwsize = packet.hwsize,
        .prosize = packet.prosize,
        .opcode = @intFromEnum(Opcode.arp_reply),
    };

    var ipv4 = arp.*;
    ipv4.daddr = arp.saddr;
    ipv4.saddr = self.ethernet.dev.ipaddr;
    std.mem.copyForwards(u8, ipv4.dmac[0..], arp.smac[0..]);
    std.mem.copyForwards(u8, ipv4.smac[0..], self.ethernet.dev.hwaddr[0..]);

    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &header);
    }

    const buffer = try self.allocator.alloc(u8, @sizeOf(Header) + @sizeOf(ARPIPv4));
    defer self.allocator.free(buffer);

    std.mem.copyForwards(u8, buffer[0..], &std.mem.toBytes(header));
    std.mem.copyForwards(u8, buffer[@sizeOf(Header)..], &std.mem.toBytes(ipv4));
    std.debug.print("[ARP] {s} is at {s}\n", .{
        Utils.ntop(arp.daddr),
        Utils.macfmt(ipv4.smac),
    });
    try self.ethernet.transmit(buffer, ipv4.dmac, .arp);
}

pub fn handle(self: *Self, frame: *const Ethernet.Frame) void {
    var packet = std.mem.bytesToValue(Header, frame.data[0..]);

    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &packet);
    }

    const proto = Proto.fromInt(packet.proto) catch return;
    const hwtype = HWType.fromInt(packet.hwtype) catch return;
    const opcode = Opcode.fromInt(packet.opcode) catch return;

    // TODO: later we should add other protocols and hardware types...
    if (proto != .IPV4) return;
    if (hwtype != .Ethernet) return;

    switch (opcode) {
        .arp_request => {
            // we must ensure this is the right protocol before doing this,
            // otherwise we might risk undefined behavior.
            const ipv4 = std.mem.bytesToValue(
                ARPIPv4,
                frame.data[@sizeOf(Header)..][0..@sizeOf(ARPIPv4)],
            );
            std.debug.print("[ARP] Who has {s}? Tell {s}\n", .{
                Utils.ntop(ipv4.daddr),
                Utils.ntop(ipv4.saddr),
            });
            const merged = self.merge(&packet, &ipv4);
            if (ipv4.daddr != self.ethernet.dev.ipaddr) return;
            if (!merged) self.insertEntry(&packet, &ipv4);
            if (opcode == .arp_request) self.reply(&packet, &ipv4) catch return;
        },
        .arp_reply => {
            const ipv4 = std.mem.bytesToValue(
                ARPIPv4,
                frame.data[@sizeOf(Header)..][0..@sizeOf(ARPIPv4)],
            );

            std.debug.print("[ARP] {s} is at {s}\n", .{
                Utils.ntop(ipv4.saddr),
                Utils.macfmt(ipv4.smac),
            });

            self.mutex.lock();
            defer self.mutex.unlock();

            // TODO: use a HashMap(addr, mac) instead of ArrayList
            for (self.cache.items) |*entry| {
                if (entry.saddr == ipv4.saddr) {
                    std.mem.copyForwards(u8, entry.smac[0..], ipv4.smac[0..]);
                    entry.state = .resolved;
                    entry.resolved.signal();
                    break;
                }
            }
        },
        .rarp_request => {},
        .rarp_reply => {},
    }
}
