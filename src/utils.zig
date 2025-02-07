const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

pub fn pton(str: []const u8) !u32 {
    var ipv4: [4]u8 = undefined;
    var i: usize = 0;
    var split = std.mem.splitScalar(u8, str, '.');
    while (split.next()) |octet| {
        if (i >= 4) break;
        ipv4[i] = try std.fmt.parseInt(u8, octet, 10);
        i += 1;
    }
    return std.mem.readInt(u32, &ipv4, native_endian);
}

pub fn ntop(addr: u32) ![]u8 {
    var buf: [16]u8 = undefined;
    const bytes = std.mem.toBytes(addr);
    try std.fmt.bufPrint(buf[0..], "{d}.{d}.{d}.{d}", .{
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
    });
    return buf;
}
