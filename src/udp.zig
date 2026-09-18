const std = @import("std");

pub const UdpHeader = packed struct(u64) {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
};

pub const UdpDatagram = struct {
    header: UdpHeader,
    payload: []const u8,
};

pub const ParseError = error{
    DatagramTooShort,
    InvalidLength,
    LengthExceedsBuffer,
};

pub fn parse(data: []const u8) ParseError!UdpDatagram {
    if (data.len < 8) return error.DatagramTooShort;

    var base: UdpHeader = @bitCast(data[0..8].*);
    base.src_port = std.mem.bigToNative(u16, base.src_port);
    base.dest_port = std.mem.bigToNative(u16, base.dest_port);
    base.length = std.mem.bigToNative(u16, base.length);
    base.checksum = std.mem.bigToNative(u16, base.checksum);

    if (base.length < 8) return error.InvalidLength;
    if (base.length > data.len) return error.LengthExceedsBuffer;

    return .{
        .header = base,
        .payload = data[8..base.length],
    };
}

test "UDP payload respects length field" {
    var data = [_]u8{
        0x1F, 0x90, // source port: 8080
        0x00, 0x50, // destination port: 80
        0x00, 0x0B, // length: 11
        0x00, 0x00, // checksum
        'h',  'i',
        '!',
        0xAA, 0xBB, 0xCC, 0xDD, // extra bytes
    };

    const datagram = try parse(&data);

    try std.testing.expectEqualSlices(u8, "hi!", datagram.payload);
}
