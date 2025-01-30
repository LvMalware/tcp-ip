const std = @import("std");
const Tap = @import("tap.zig");
const Ethernet = @import("ethernet.zig");

pub fn main() !void {
    var dev = try Tap.Device.init(null);
    defer dev.deinit();

    try dev.ifup("", "");

    std.debug.print("Interface: {s}\n", .{dev.name});

    const eth = Ethernet.Header{
        .dmac = [_]u8{'A'} ** 6,
        .smac = [_]u8{'B'} ** 6,
        .type = 67,
        .data = undefined,
    };
    const stdout = std.io.getStdOut().writer();
    _ = try stdout.writeStructEndian(eth, .big);
}
