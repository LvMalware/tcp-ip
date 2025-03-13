const std = @import("std");
const IPv4 = @import("ipv4.zig");

const Self = @This();

pub const vtable = IPv4.Handler.VTable{
    .handle = vhandle,
};

pub const ICMPType = enum(u8) {
    ECHOREPLY = 0,
    DEST_UNREACH = 3,
    SOURCE_QUENCH = 4,
    REDIRECT = 5,
    ECHO = 8,
    TIME_EXCEEDED = 11,
    PARAMETERPROB = 12,
    TIMESTAMP = 13,
    TIMESTAMPREPLY = 14,
    INFO_REQUEST = 15,
    INFO_REPLY = 16,
    ADDRESS = 17,
    ADDRESSREPLY = 18,
    pub fn fromInt(val: u8) !ICMPType {
        return try std.meta.intToEnum(ICMPType, val);
    }
};

pub const Header = extern struct {
    type: u8 align(1),
    code: u8 align(1),
    csum: u16 align(1),
    pub fn fromBytes(bytes: []const u8) Header {
        return std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
    }
    pub fn checksum(self: Header, data: []const u8) u16 {
        var csum: u32 = 0;
        const hwords = std.mem.bytesAsSlice(u16, std.mem.asBytes(&self));
        for (hwords) |w| csum += w;
        const dwords = std.mem.bytesAsSlice(u16, data);
        for (dwords) |w| csum += w;

        while (csum >> 16 != 0) {
            csum = (csum & 0xffff) + (csum >> 16);
        }
        return @truncate(~csum);
    }
    pub fn validChecksum(self: Header, data: []const u8) bool {
        return self.checksum(data) == 0;
    }
};

pub const EchoRequest = extern struct {
    id: u16 align(1),
    seq: u16 align(1),
    pub fn fromBytes(bytes: []const u8) EchoRequest {
        return std.mem.bytesToValue(EchoRequest, bytes[0..@sizeOf(EchoRequest)]);
    }
};

ip: *IPv4,
sent: std.ArrayList(EchoRequest),
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, ip: *IPv4) Self {
    return .{
        .ip = ip,
        .sent = std.ArrayList(EchoRequest).init(allocator),
        .allocator = allocator,
    };
}

fn vhandle(ctx: *anyopaque, packet: *const IPv4.Packet) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.handle(packet);
}

pub fn deinit(self: *Self) void {
    self.sent.deinit();
}

pub fn echoReply(self: *Self, dst: u32, data: []const u8) !void {
    var header: Header = .{
        .type = @intFromEnum(ICMPType.ECHOREPLY),
        .code = 0,
        .csum = 0,
    };
    header.csum = header.checksum(data);
    const buffer = try self.allocator.alloc(u8, @sizeOf(Header) + data.len);
    defer self.allocator.free(buffer);
    std.mem.copyForwards(u8, buffer, &std.mem.toBytes(header));
    std.mem.copyForwards(u8, buffer[@sizeOf(Header)..], data);
    try self.ip.send(null, dst, .ICMP, buffer);
}

pub fn echoRequest(self: *Self, dst: u32) !void {
    // TODO: each echo request must be related to a target host...
    _ = .{ self, dst };
    return error.NotImplemented;
}

pub fn handle(self: *Self, packet: *const IPv4.Packet) void {
    const data = packet.data[@sizeOf(Header)..];
    const header = Header.fromBytes(packet.data);
    const htype = ICMPType.fromInt(header.type) catch return;
    std.debug.print("[ICMPv4] received ICMP {s}\n", .{@tagName(htype)});
    switch (htype) {
        .ECHO => {
            self.echoReply(
                packet.header.saddr,
                data,
            ) catch return;
        },
        else => return,
    }
}

pub fn handler(self: *Self) IPv4.Handler {
    return .{ .vtable = &vtable, .ptr = self };
}
