const std = @import("std");
const ipv4 = @import("ipv4.zig");

test "parse extracts every field correctly from a well-formed packet" {
    const data = [_]u8{
        0x45, // version=4, ihl=5 (20-byte header, no options)
        0xA9, // dscp=42, ecn=1
        0x00, 0x1A, // total_length = 26 (20 header + 6 payload)
        0xBE, 0xEF, // identification = 0xBEEF
        0x40, 0x19, // flags=2 (010), fragment_offset=25
        0x40, // ttl = 64
        0x06, // protocol = 6 (TCP)
        0xCA, 0xFE, // checksum = 0xCAFE
        0xC0, 0xA8, 0x01, 0x01, // source = 192.168.1.1
        0x0A, 0x00, 0x00, 0x05, // destination = 10.0.0.5
        'H', 'E', 'L', 'L', 'O', '!', // payload
    };

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqual(@as(u4, 4), packet.header.version);
    try std.testing.expectEqual(@as(u4, 5), packet.header.ihl);
    try std.testing.expectEqual(@as(u6, 42), packet.header.dscp);
    try std.testing.expectEqual(@as(u2, 1), packet.header.ecn);
    try std.testing.expectEqual(@as(u16, 26), packet.header.total_length);
    try std.testing.expectEqual(@as(u16, 0xBEEF), packet.header.identification);
    try std.testing.expectEqual(@as(u3, 2), packet.header.flags);
    try std.testing.expectEqual(@as(u13, 25), packet.header.fragment_offset);
    try std.testing.expectEqual(@as(u8, 64), packet.header.ttl);
    try std.testing.expectEqual(@as(u8, 6), packet.header.protocol);
    try std.testing.expectEqual(@as(u16, 0xCAFE), packet.header.checksum);

    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &packet.source);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 5 }, &packet.destination);

    try std.testing.expectEqual(@as(u8, 20), packet.header_length);
    try std.testing.expectEqual(@as(usize, 0), packet.options.len);
    try std.testing.expectEqualStrings("HELLO!", packet.payload);
}

test "parse correctly separates dscp and ecn instead of swapping them" {
    // byte1 = 0xAD = 1010_1101 -> top 6 bits (dscp) = 101011 = 43,
    // bottom 2 bits (ecn) = 01 = 1. If these were swapped (the bug we
    // fixed), this would come back as dscp=1, ecn=43 instead.
    var data = [_]u8{0} ** 20;
    data[0] = 0x45; // version 4, ihl 5
    data[1] = 0xAD;
    data[3] = 20; // total_length = 20 (header only, no payload)

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqual(@as(u6, 43), packet.header.dscp);
    try std.testing.expectEqual(@as(u2, 1), packet.header.ecn);
}

test "parse reads multi-byte fields as big-endian, not native" {
    var data = [_]u8{0} ** 20;
    data[0] = 0x45;
    data[3] = 20; // total_length = 20

    data[4] = 0x12;
    data[5] = 0x34; // identification = 0x1234, not 0x3412
    data[10] = 0xAB;
    data[11] = 0xCD; // checksum = 0xABCD, not 0xCDAB

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqual(@as(u16, 0x1234), packet.header.identification);
    try std.testing.expectEqual(@as(u16, 0xABCD), packet.header.checksum);
}

test "parse extracts options when ihl indicates a header longer than 20 bytes" {
    const data = [_]u8{
        0x46, // version=4, ihl=6 -> 24-byte header
        0x00,
        0x00, 0x1A, // total_length = 26 (24 header + 2 payload)
        0x00, 0x00,
        0x00, 0x00,
        0x0A, // ttl
        0x11, // protocol = 17 (UDP)
        0x00,
        0x00,
        1, 1, 1, 1, // source
        2, 2, 2, 2, // destination
        0x01, 0x02, 0x03, 0x04, // options (4 bytes, since ihl=6 -> 24 - 20 = 4)
        'O', 'K', // payload
    };

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqual(@as(u8, 24), packet.header_length);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, packet.options);
    try std.testing.expectEqualStrings("OK", packet.payload);
}

test "parse ignores trailing bytes beyond total_length" {
    // Simulates link-layer padding after a short IPv4 packet: total_length
    // says the packet ends at byte 22, but the buffer is 26 bytes long.
    var data = [_]u8{0} ** 26;
    data[0] = 0x45; // ihl=5 -> 20-byte header
    data[3] = 22; // total_length = 22 (20 header + 2 payload)
    data[20] = 'O';
    data[21] = 'K';
    data[22] = 0xFF; // padding — must NOT end up in payload
    data[23] = 0xFF;
    data[24] = 0xFF;
    data[25] = 0xFF;

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqualStrings("OK", packet.payload);
}

test "parse rejects a buffer shorter than the minimum 20-byte header" {
    const data = [_]u8{0} ** 19;
    try std.testing.expectError(ipv4.IPv4BaseHeader.ParseError.PacketTooShort, ipv4.parse(&data));
}

test "parse rejects a non-IPv4 version" {
    var data = [_]u8{0} ** 20;
    data[0] = 0x65; // version=6, ihl=5
    try std.testing.expectError(ipv4.IPv4BaseHeader.ParseError.InvalidVersion, ipv4.parse(&data));
}

test "parse rejects an ihl smaller than the minimum valid header size" {
    var data = [_]u8{0} ** 20;
    data[0] = 0x44; // version=4, ihl=4 -> 16-byte header, invalid (min is 5)
    try std.testing.expectError(ipv4.IPv4BaseHeader.ParseError.InvalidHeaderLength, ipv4.parse(&data));
}

test "parse rejects a buffer shorter than what ihl claims the header needs" {
    var data = [_]u8{0} ** 20; // only 20 bytes provided
    data[0] = 0x46; // ihl=6 -> claims a 24-byte header
    try std.testing.expectError(ipv4.IPv4BaseHeader.ParseError.PacketTooShort, ipv4.parse(&data));
}

test "parse rejects total_length smaller than the header it claims" {
    var data = [_]u8{0} ** 20;
    data[0] = 0x45; // ihl=5 -> 20-byte header
    data[3] = 10; // total_length = 10, less than the 20-byte header itself
    try std.testing.expectError(
        ipv4.IPv4BaseHeader.ParseError.TotalLengthMismatch,
        ipv4.parse(&data),
    );
}

test "parse rejects total_length larger than the actual buffer" {
    var data = [_]u8{0} ** 20; // no payload bytes actually present
    data[0] = 0x45;
    data[3] = 100; // total_length claims 100 bytes total
    try std.testing.expectError(
        ipv4.IPv4BaseHeader.ParseError.TotalLengthMismatch,
        ipv4.parse(&data),
    );
}

test "parse accepts the maximum possible ihl (15 -> 60-byte header)" {
    var data = [_]u8{0} ** 62; // 60-byte header + 2-byte payload
    data[0] = 0x4F; // version=4, ihl=15 (max value a u4 can hold)
    data[3] = 62; // total_length = 62 (60 header + 2 payload)
    data[60] = 'O';
    data[61] = 'K';

    const packet = try ipv4.parse(&data);

    try std.testing.expectEqual(@as(u8, 60), packet.header_length);
    try std.testing.expectEqual(@as(usize, 40), packet.options.len); // 60 - 20 fixed bytes
    try std.testing.expectEqualStrings("OK", packet.payload);
}
