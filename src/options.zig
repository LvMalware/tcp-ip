const std = @import("std");

// from: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
pub const Kind = enum(u8) {
    END = 0,
    NOP = 1,
    MSS = 2,
    WINDOW_SCALE = 3,
    SACK_PERMITTED = 4, // selective acknowledgement (RFC 2018)
    SACK = 5,
    TIMESTAMP = 8,
    pub fn fromInt(val: u8) !Kind {
        return std.meta.intToEnum(Kind, val) catch {
            std.debug.print("[OPTIONS] Unknown option kind: {d}\n", .{val});
            return error.UnknownOption;
        };
    }
};

pub const EndOption = struct {
    pub fn size(self: EndOption) usize {
        _ = .{self};
        return 1;
    }
    pub fn toBytes(self: EndOption, bytes: []u8) void {
        _ = .{self};
        bytes[0] = @intFromEnum(Kind.END);
    }
};

pub const NopOption = struct {
    pub fn size(self: NopOption) usize {
        _ = .{self};
        return 1;
    }
    pub fn toBytes(self: NopOption, bytes: []u8) void {
        _ = .{self};
        bytes[0] = @intFromEnum(Kind.NOP);
    }
};

pub const MSSOption = struct {
    data: u16, // maximum segment size
    pub fn size(self: MSSOption) usize {
        _ = .{self};
        return 4;
    }
    pub fn fromBytes(bytes: []const u8) MSSOption {
        return .{
            .data = std.mem.readInt(u16, bytes[2..4], .big),
        };
    }
    pub fn toBytes(self: MSSOption, bytes: []u8) void {
        bytes[0] = @intFromEnum(Kind.MSS);
        bytes[1] = @truncate(self.size());
        std.mem.writeInt(u16, bytes[2..][0..2], self.data, .big);
    }
};

pub const SACKPermittedOption = struct {
    data: bool = true,
    pub fn size(self: SACKPermittedOption) usize {
        _ = .{self};
        return 2;
    }

    pub fn toBytes(self: SACKPermittedOption, bytes: []u8) void {
        bytes[0] = @intFromEnum(Kind.SACK_PERMITTED);
        bytes[1] = @truncate(self.size());
    }
};

pub const SACKOption = struct {
    const Edge = extern struct {
        left: u32 align(1),
        right: u32 align(1),
    };
    data: [4]?Edge = .{null} ** 4,

    pub fn size(self: SACKOption) usize {
        var count: usize = 0;
        for (self.data) |i| {
            if (i != null) count += 1;
        }
        return 2 + 8 * count;
    }

    pub fn fromBytes(data: []const u8) SACKOption {
        var opt: SACKOption = .{};
        const length = data[1] - 2;
        for (std.mem.bytesAsSlice(Edge, data[2 .. 2 + length]), 0..) |e, i| {
            opt.data[i] = .{
                .left = std.mem.bigToNative(u32, e.left),
                .right = std.mem.bigToNative(u32, e.right),
            };
        }
        return opt;
    }
    pub fn toBytes(self: SACKOption, bytes: []u8) void {
        _ = .{ self, bytes };
        // TODO
    }
};

const TimestampOption = struct {
    tsval: u32,
    tsecr: u32,
    pub fn size(self: TimestampOption) usize {
        _ = .{self};
        return 10;
    }

    pub fn fromBytes(data: []const u8) TimestampOption {
        return .{
            .tsval = std.mem.readInt(u32, data[2..6], .big),
            .tsecr = std.mem.readInt(u32, data[6..10], .big),
        };
    }

    pub fn toBytes(self: TimestampOption, bytes: []u8) void {
        _ = .{ self, bytes };
    }
};

pub const WindowScaleOption = struct {
    data: u8, // shift count
    pub fn size(self: WindowScaleOption) usize {
        _ = .{self};
        return 3;
    }
    pub fn toBytes(self: WindowScaleOption, bytes: []u8) void {
        bytes[0] = @intFromEnum(Kind.WINDOW_SCALE);
        bytes[1] = @truncate(self.size());
        bytes[2] = self.data;
    }
};

pub const Option = union(Kind) {
    END: EndOption,
    NOP: NopOption,
    MSS: MSSOption,
    WINDOW_SCALE: WindowScaleOption,
    SACK_PERMITTED: SACKPermittedOption,
    SACK: SACKOption,
    TIMESTAMP: TimestampOption,

    pub fn fromBytes(bytes: []const u8) !Option {
        const kind = try Kind.fromInt(bytes[0]);
        return switch (kind) {
            .END => .{ .END = .{} },
            .NOP => .{ .NOP = .{} },
            .MSS => .{
                .MSS = MSSOption.fromBytes(bytes),
            },
            .WINDOW_SCALE => .{ .WINDOW_SCALE = .{ .data = bytes[2] } },
            .SACK => .{ .SACK = SACKOption.fromBytes(bytes) },
            .SACK_PERMITTED => .{ .SACK_PERMITTED = .{} },
            .TIMESTAMP => .{ .TIMESTAMP = TimestampOption.fromBytes(bytes) },
        };
    }

    pub fn toBytes(self: Option, bytes: []u8) void {
        switch (self) {
            inline else => |o| o.toBytes(bytes),
        }
    }

    pub fn size(self: Option) usize {
        return switch (self) {
            inline else => |o| o.size(),
        };
    }
};
