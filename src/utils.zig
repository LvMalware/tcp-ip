const std = @import("std");

pub fn pton(str: []const u8) !u32 {
    var ipv4: [4]u8 = undefined;
    var i: usize = 0;
    var split = std.mem.splitScalar(u8, str, '.');
    while (split.next()) |octet| {
        if (i >= 4) break;
        ipv4[i] = try std.fmt.parseInt(u8, octet, 10);
        i += 1;
    }
    return std.mem.readInt(u32, &ipv4, .little);
}

pub fn ntop(u: u32) [16]u8 {
    var buf: [16]u8 = undefined;
    const bytes = std.mem.toBytes(u);
    _ = std.fmt.bufPrint(buf[0..], "{d}.{d}.{d}.{d}", .{
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
    }) catch {};
    return buf;
}

pub fn macfmt(m: [6]u8) [17]u8 {
    var buf: [17]u8 = undefined;
    _ = std.fmt.bufPrint(
        buf[0..],
        "{x:0<2}:{x:0<2}:{x:0<2}:{x:0<2}:{x:0<2}:{x:0<2}",
        .{
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5],
        },
    ) catch {};
    return buf;
}
