const std = @import("std");

pub const Header = extern struct {
    dmac: [6]u8,
    smac: [6]u8,
    type: u16,
    // tags: u32,
    data: [1500]u8,
};
