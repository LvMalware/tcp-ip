const std = @import("std");
const linux = std.os.linux;
const native_endian = @import("builtin").target.cpu.arch.endian();

const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: u32 = 0x400454ca;

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
            return error.IOCTL;
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

    fn setIPv4Addr(self: *Device, ip: []const u8) !void {
        var ipv4: [4]u8 = undefined;
        var i: usize = 0;
        var split = std.mem.splitScalar(u8, ip, '.');
        while (split.next()) |octet| {
            if (i >= 4) break;
            ipv4[i] = try std.fmt.parseInt(u8, octet, 10);
            i += 1;
        }
        // self.ipaddr = std.mem.nativeToBig(u32, std.mem.readInt(u32, &ipv4, native_endian));
        self.ipaddr = std.mem.readInt(u32, &ipv4, native_endian);
    }

    pub fn ifup(self: *Device, mac: []const u8, ip: []const u8) !void {
        try self.setHWAddr(mac);
        try self.setIPv4Addr(ip);

        _ = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "ip",
                "link",
                "set",
                &self.name,
                "up",
            },
        });

        const cidr = try std.mem.concat(self.allocator, u8, &[_][]const u8{
            ip[0..std.mem.lastIndexOfScalar(u8, ip, '.').?],
            ".1/24",
        });

        // std.debug.print("CIDR: {s}\n", .{cidr});

        // _ = try std.process.Child.run(.{ .allocator = self.allocator, .argv = &[_][]const u8{ "ip", "route", "add", "dev", &self.name, cidr } });
        // _ = try std.process.Child.run(.{ .allocator = self.allocator, .argv = &[_][]const u8{ "ip", "address", "add", "dev", &self.name, "local", ip } });

        _ = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "ip",
                "addr",
                "add",
                cidr,
                "dev",
                &self.name,
            },
        });
    }

    pub fn ifdown(self: Device) !void {
        _ = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "ip",
                "link",
                "set",
                &self.name,
                "down",
            },
        });
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
