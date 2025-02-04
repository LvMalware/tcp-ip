const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

const IPv4 = @import("ipv4.zig");
const Self = @This();

const vtable = IPv4.Handler.VTable{ .handle = vhandle };

const Flags = switch (native_endian) {
    .little => packed struct {
        cwr: bool,
        ece: bool,
        urg: bool,
        ack: bool,
        psh: bool,
        rst: bool,
        syn: bool,
        fin: bool,
    },
    .big => packed struct {
        cwr: bool,
        ece: bool,
        urg: bool,
        ack: bool,
        psh: bool,
        rst: bool,
        syn: bool,
        fin: bool,
    },
};

const Header = extern struct {
    sport: u16 align(1),
    dport: u16 align(1),
    seq: u32 align(1),
    ack: u32 align(1),
    rsv_flags: u16 align(1), // data offset, reserved bytes and flags
    window: u16 align(1),
    csum: u16 align(1),
    urgent: u16 align(1),
    optpad: u32 align(1), // options and padding

    pub fn fromBytes(bytes: []const u8) Header {
        return std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
    }

    pub fn checksum(self: Header, data: []const u8) u16 {
        _ = .{ self, data };
        return 0;
    }

    pub fn validChecksum(self: Header, data: []const u8) bool {
        _ = .{ self, data };
        return self.checksum(data) == 0;
    }

    pub fn getFlags(self: Header) Flags {
        //return std.mem.bytesToValue(Flags, &[_]u8{self.flags});
        _ = .{self};
        return undefined;
    }

    pub fn dataOffset(self: Header) usize {
        _ = .{self};
        return @sizeOf(Header);
        //switch (native_endian) {
        //    .big => self.rsv & 0xf,
        //    .little => self.rsv >> 4,
        //} * 4;
    }
};

const Segment = struct {
    header: Header,
    data: []const u8,
};

ip: *IPv4,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, ip: *IPv4) Self {
    return .{
        .ip = ip,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    _ = .{self};
}

pub fn handler(self: *Self) IPv4.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}

pub fn handle(self: *Self, packet: *const IPv4.Packet) void {
    std.debug.print("Handlign TCP packet!\n", .{});
    _ = .{ self, packet };
    var header = Header.fromBytes(packet.data);

    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Header, &header);
    }

    const segment = Segment{
        .header = header,
        .data = packet.data[header.dataOffset()..],
    };

    const flags = segment.header.getFlags();

    std.debug.print("SEQ={d}, LEN={d}, SYN={}\n", .{ segment.header.seq, segment.data.len, flags.syn });
}

fn vhandle(ctx: *anyopaque, packet: *const IPv4.Packet) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(packet);
}
