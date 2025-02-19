const std = @import("std");

// from: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
pub const Kind = enum(u8) {
    END = 0,
    NOP = 1,
    MSS = 2,
    WINDOW_SCALE = 3,
    SACK_PERMITTED = 4, // selective acknowledgement (RFC 2018)
    SACK = 5,
    pub fn fromInt(val: u8) !Kind {
        return std.meta.intToEnum(Kind, val) catch return error.UnknownOption;
    }
};

pub const EndOption = struct {
    pub fn size(self: EndOption) usize {
        _ = .{self};
        return 1;
    }
};

pub const NopOption = struct {
    pub fn size(self: NopOption) usize {
        _ = .{self};
        return 1;
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
};

pub const SACKPermittedOption = struct {
    data: bool = true,
    pub fn size(self: SACKPermittedOption) usize {
        _ = .{self};
        return 2;
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
};

pub const WindowScaleOption = struct {
    data: u8, // shift count
    pub fn size(self: WindowScaleOption) usize {
        _ = .{self};
        return 3;
    }
};

pub const Option = union(Kind) {
    END: EndOption,
    NOP: NopOption,
    MSS: MSSOption,
    WINDOW_SCALE: WindowScaleOption,
    SACK_PERMITTED: SACKPermittedOption,
    SACK: SACKOption,

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
        };
    }

    pub fn size(self: Option) usize {
        return switch (self) {
            inline else => |o| o.size(),
        };
    }
};
