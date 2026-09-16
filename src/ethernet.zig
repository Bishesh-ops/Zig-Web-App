const std = @import("std");
pub const EthernetFrame = struct {
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16,
    payload: []const u8,
};
pub fn parseEthernet(data: []const u8) !EthernetFrame {
    if (data.len < 14) return error.FrameTooShort;
    const dest_mac = data[0..6].*;
    const src_mac = data[6..12].*;
    const ether_type = std.mem.readInt(u16, data[12..14], .big);
    const payload = data[14..];

    return .{
        .dest_mac = dest_mac,
        .src_mac = src_mac,
        .ether_type = ether_type,
        .payload = payload,
    };
}
