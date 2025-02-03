const std = @import("std");

const IPv4 = @import("ip.zig");
const Tap = @import("tap.zig");
const Arp = @import("arp.zig");
const Ethernet = @import("ethernet.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var dev = try Tap.Device.init(allocator, null);
    defer dev.deinit();
    try dev.ifup("AA:AA:AA:AA:AA:AA", "10.0.0.4");

    var eth = Ethernet.init(allocator, &dev);
    defer eth.deinit();

    var arp = Arp.init(allocator, &eth);
    defer arp.deinit();

    var ip = IPv4.init(allocator, &arp, &eth);
    defer ip.deinit();

    try eth.addProtocolHandler(
        .arp,
        arp.handler(),
    );

    try eth.addProtocolHandler(
        .ip4,
        ip.handler(),
    );

    try ip.send(null, 0x0100000a, .IPPROTO_IP, "hello");

    while (true) {
        try eth.readAndDispatch();
    }
}
