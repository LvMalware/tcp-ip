const std = @import("std");

const Tap = @import("tap.zig");
const TCP = @import("tcp.zig");
const Arp = @import("arp.zig");
const IPv4 = @import("ipv4.zig");
const ICMP4 = @import("icmp4.zig");
const Socket = @import("socket.zig");
const Ethernet = @import("ethernet.zig");

pub fn clientLoop(allocator: std.mem.Allocator, tcp: *TCP) void {
    defer std.debug.print("Client loop finished\n", .{});
    var buffer: [1024]u8 = undefined;
    var client = Socket.init(allocator, tcp);
    defer client.deinit();
    std.debug.print("Connecting...\n", .{});
    client.connect("10.0.0.4", 5501) catch return;
    while (client.state() == .ESTABLISHED) {
        const size = client.read(buffer[0..]) catch return;
        std.debug.print("[Client] Received: {s}\n", .{buffer[0..size]});
        _ = client.write("Pong!") catch return;
    }
}

pub fn serverLoop(allocator: std.mem.Allocator, tcp: *TCP) void {
    defer std.debug.print("Server loop finished\n", .{});
    var server = Socket.init(allocator, tcp);
    defer server.deinit();

    var clients = std.ArrayList(*Socket).init(allocator);
    defer {
        for (clients.items) |i| i.deinit();
        clients.deinit();
    }
    var buffer: [1024]u8 = undefined;
    server.listen("10.0.0.4", 5501) catch return;
    std.debug.print("Listenning...\n", .{});
    while (true) {
        if (server.events.read > 0) {
            std.debug.print("Accepted connection!\n", .{});
            var client = server.accept() catch return;

            clients.append(client) catch {
                client.deinit();
                return;
            };
            std.time.sleep(1 * std.time.ns_per_s);
            _ = client.write("Ping!") catch {};
        }

        for (clients.items) |c| {
            if (c.events.read > 0) {
                const size = c.read(buffer[0..]) catch {
                    c.deinit();
                    continue;
                };
                if (size == 0) {
                    std.debug.print("Deinit client\n", .{});
                    c.deinit();
                    continue;
                }
                std.debug.print("[Server] Received: {s}\n", .{buffer[0..size]});
                _ = c.write("Ping!") catch {
                    c.deinit();
                    continue;
                };
            }
        }
    }
}

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
    var server = try std.Thread.spawn(.{}, serverLoop, .{ allocator, &tcp });
    defer server.join();

    var client = try std.Thread.spawn(.{}, clientLoop, .{ allocator, &tcp });
    defer client.join();

    std.debug.print("[Ethernet] OK\n", .{});
    while (true) {
        try eth.readAndDispatch();
    }
}
