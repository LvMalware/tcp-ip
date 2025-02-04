const std = @import("std");

const Tap = @import("tap.zig");
const TCP = @import("tcp.zig");
const Arp = @import("arp.zig");
const IPv4 = @import("ipv4.zig");
const ICMP4 = @import("icmp4.zig");
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

    var tcp = TCP.init(allocator, &ip);
    defer tcp.deinit();

    var icmp = ICMP4.init(allocator, &ip);
    defer icmp.deinit();

    try eth.addProtocolHandler(.ip4, ip.handler());
    try eth.addProtocolHandler(.arp, arp.handler());
    try ip.addProtocolHandler(.ICMP, icmp.handler());
    try ip.addProtocolHandler(.TCP, tcp.handler());

    // try ip.send(null, 0x0100000a, .IP, "hello");

    while (true) {
        try eth.readAndDispatch();
    }
}
