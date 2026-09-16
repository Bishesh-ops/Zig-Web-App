const std = @import("std");
pub const EthernetFrame = struct {
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: EtherType,
    payload: []const u8,
};

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    _,
};

pub fn parse(data: []const u8) !EthernetFrame {
    if (data.len < 14) return error.FrameTooShort;
    const dest_mac = data[0..6].*;
    const src_mac = data[6..12].*;
    const raw_ether_type = std.mem.readInt(u16, data[12..14], .big);
    const payload = data[14..];

    const ether_type: EtherType = @enumFromInt(raw_ether_type);

    return .{
        .dest_mac = dest_mac,
        .src_mac = src_mac,
        .ether_type = ether_type,
        .payload = payload,
    };
}
