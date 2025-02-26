const std = @import("std");
const linux = std.os.linux;
const native_endian = @import("builtin").target.cpu.arch.endian();

const Utils = @import("utils.zig");

const IFF_UP: u16 = 0x0001;
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const IFF_RUNNING: i16 = 0x0040;

const TUNSETIFF: u32 = 0x400454ca;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFHWADDR: u32 = 0x8924;
const SIOCSIFNETMASK: u32 = 0x891c;

pub const Device = struct {
    pub const Reader = std.io.Reader(Device, anyerror, read);
    pub const Writer = std.io.Writer(Device, anyerror, write);

    fd: std.posix.fd_t,
    name: [linux.IFNAMESIZE]u8,
    hwaddr: [6]u8,
    ipaddr: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, ifname: ?[]u8) !Device {
        var ifr = std.mem.zeroes(linux.ifreq);
        var dev = Device{
            .fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0),
            .name = undefined,
            .ipaddr = 0,
            .hwaddr = undefined,
            .allocator = allocator,
        };

        if (ifname) |name| std.mem.copyForwards(u8, ifr.ifrn.name[0..], name);
        ifr.ifru.flags = IFF_TAP | IFF_NO_PI;

        if (linux.ioctl(dev.fd, TUNSETIFF, @intFromPtr(&ifr)) != 0) {
            std.posix.close(dev.fd);
            return error.IoCtl;
        }

        std.mem.copyForwards(u8, dev.name[0..], &ifr.ifrn.name);

        return dev;
    }

    fn setHWAddr(self: *Device, mac: []const u8) !void {
        var i: usize = 0;
        var split = std.mem.splitScalar(u8, mac, ':');
        while (split.next()) |hex| {
            if (i >= 6) break;
            self.hwaddr[i] = try std.fmt.parseInt(u8, hex, 16);
            i += 1;
        }
    }

    pub fn ifup(self: *Device, mac: []const u8, ip: []const u8) !void {
        try self.setHWAddr(mac);

        self.ipaddr = try Utils.pton(ip);

        var sin = std.mem.zeroInit(linux.sockaddr.in, .{
            .addr = try Utils.pton("10.0.0.1"),
        });

        // we need a socket to use SIOCSIFADDR and other netdev IOCTLs
        const sock: linux.fd_t = @bitCast(
            @as(u32, @truncate(linux.socket(sin.family, linux.SOCK.DGRAM, 0))),
        );

        if (sock < 0) return error.Socket;

        defer _ = linux.close(sock);

        var ifr = linux.ifreq{
            // our tap interface is identified by the name
            .ifrn = .{ .name = self.name },
            .ifru = .{
                .addr = .{
                    .family = linux.AF.INET,
                    .data = std.mem.asBytes(&sin)[2..].*,
                },
            },
        };

        if (linux.ioctl(sock, SIOCSIFADDR, @intFromPtr(&ifr)) != 0) {
            return error.IFADDR;
        }

        sin.addr = try Utils.pton("255.255.255.0");

        ifr.ifru.netmask = .{
            .family = linux.AF.INET,
            .data = std.mem.asBytes(&sin)[2..].*,
        };

        if (linux.ioctl(sock, SIOCSIFNETMASK, @intFromPtr(&ifr)) != 0) {
            return error.IFNETMASK;
        }

        if (linux.ioctl(sock, SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.GETFLAGS;
        }

        ifr.ifru.flags |= IFF_UP;

        if (linux.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.IFUP;
        }

        // _ = try std.process.Child.run(.{
        //     .allocator = self.allocator,
        //     .argv = &[_][]const u8{
        //         "ip",
        //         "link",
        //         "set",
        //         &self.name,
        //         "up",
        //     },
        // });
    }

    pub fn ifdown(self: Device) !void {
        const sock: linux.fd_t = @bitCast(
            @as(u32, @truncate(linux.socket(2, linux.SOCK.DGRAM, 0))),
        );

        if (sock < 0) return error.Socket;

        defer _ = linux.close(sock);

        var ifr = linux.ifreq{
            .ifrn = .{ .name = self.name },
            .ifru = undefined,
        };

        if (linux.ioctl(sock, SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.GETFLAGS;
        }

        ifr.ifru.flags |= IFF_UP;

        if (linux.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
            return error.IFDOWN;
        }
        // _ = try std.process.Child.run(.{
        //     .allocator = self.allocator,
        //     .argv = &[_][]const u8{
        //         "ip",
        //         "link",
        //         "set",
        //         &self.name,
        //         "down",
        //     },
        // });
    }

    pub fn deinit(self: Device) void {
        std.posix.close(self.fd);
        self.ifdown() catch {};
    }

    pub fn read(self: Device, buffer: []u8) !usize {
        return try std.posix.read(self.fd, buffer);
    }

    pub fn write(self: Device, buffer: []const u8) !usize {
        return try std.posix.write(self.fd, buffer);
    }

    pub fn reader(self: Device) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: Device) Writer {
        return .{ .context = self };
    }
};
