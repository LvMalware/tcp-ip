const std = @import("std");
const linux = std.os.linux;

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

    pub fn init(ifname: ?[]u8) !Device {
        var ifr = std.mem.zeroes(linux.ifreq);
        var dev: Device = undefined;
        dev.fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);

        if (ifname) |name| std.mem.copyForwards(u8, ifr.ifrn.name[0..], name);
        ifr.ifru.flags = IFF_TAP | IFF_NO_PI;

        if (linux.ioctl(dev.fd, TUNSETIFF, @intFromPtr(&ifr)) != 0) {
            std.posix.close(dev.fd);
            return error.IOCTL;
        }

        std.mem.copyForwards(u8, dev.name[0..], &ifr.ifrn.name);

        return dev;
    }

    pub fn ifup(self: *Device, mac: []u8, ip: []u8) !void {
        _ = .{ self, mac, ip };
        // TODO: set up interface
    }

    pub fn ifdown(self: *Device) !void {
        _ = .{self};
        // TODO: ip link set interface down ...
    }

    pub fn deinit(self: Device) void {
        std.posix.close(self.fd);
    }

    pub fn read(self: Device, buffer: []u8) !usize {
        return try std.posix.read(self.fd, buffer);
    }

    pub fn write(self: Device, buffer: []u8) !usize {
        return try std.posix.write(self.fd, buffer);
    }

    pub fn reader(self: Device) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: Device) Writer {
        return .{ .context = self };
    }
};
