const std = @import("std");

const Tap = @import("tap.zig");
const TCP = @import("tcp.zig");
const Arp = @import("arp.zig");
const IPv4 = @import("ipv4.zig");
const ICMP4 = @import("icmp4.zig");
const Socket = @import("socket.zig");
const Ethernet = @import("ethernet.zig");

pub fn serverLoop(allocator: std.mem.Allocator, tcp: *TCP) void {
    var server = Socket.init(allocator, tcp);
    defer server.deinit();

    server.listen("10.0.0.4", 5501, 1) catch return;
    std.debug.print("Listenning...\n", .{});

    var client = server.accept() catch return;
    defer client.deinit();

    std.debug.print("Accepted connection!\n", .{});

    var buffer: [1024]u8 = undefined;
    while (client.state() == .ESTABLISHED) {
        const size = client.read(buffer[0..]) catch {
            continue;
        };
        if (size == 0) break;
        std.debug.print("[Server] Received: {s}\n", .{buffer[0..size]});
        _ = client.write(buffer[0..size]) catch {};
    }

    std.debug.print("Client disconnected. Finishing...\n", .{});
}

fn clientLoop(allocator: std.mem.Allocator, tcp: *TCP) void {
    var buffer: [1024]u8 = undefined;

    var client = Socket.init(allocator, tcp);
    defer client.deinit();

    std.debug.print("Connecting...\n", .{});
    client.connect("10.0.0.1", 5501) catch |err| {
        std.debug.print("Failed to connect: {s}\n", .{@errorName(err)});
        return;
    };
    std.debug.print("Connected!\n", .{});
    while (client.state() == .ESTABLISHED) {
        const size = client.read(buffer[0..]) catch return;
        if (size == 0) break;
        std.debug.print("[Client] Received: {s}\n", .{buffer[0..size]});
        _ = client.write(buffer[0..size]) catch return;
    }
    std.debug.print("Disconnected!\n", .{});
}

fn ethernetLoop(running: *std.atomic.Value(bool), eth: *Ethernet) void {
    while (running.load(.acquire)) {
        eth.readAndDispatch() catch |err| {
            std.debug.print("[ETHERNET] Failed to read frame: {s}\n", .{
                @errorName(err),
            });
            break;
        };
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

    var tcp = TCP.init(allocator, &ip, 400);
    defer tcp.deinit();

    // start retransmission
    try tcp.start();

    var icmp = ICMP4.init(allocator, &ip);
    defer icmp.deinit();

    try eth.addProtocolHandler(.ip4, ip.handler());
    try eth.addProtocolHandler(.arp, arp.handler());

    try ip.addProtocolHandler(.ICMP, icmp.handler());
    try ip.addProtocolHandler(.TCP, tcp.handler());

    var running = std.atomic.Value(bool).init(true);

    var thread = try std.Thread.spawn(.{}, ethernetLoop, .{ &running, &eth });
    defer {
        running.store(false, .release);
        thread.join();
    }

    const client: bool = findMode: {
        var iter = std.process.args();
        while (iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "client")) break :findMode true;
        }
        break :findMode false;
    };
    if (client) clientLoop(allocator, &tcp) else serverLoop(allocator, &tcp);
}
