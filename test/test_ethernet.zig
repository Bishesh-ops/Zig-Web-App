const std = @import("std");
const app = @import("app");
const ethernet = app.ethernet;

test "parse parses all fields of a well-formed frame" {
    const data = [_]u8{
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dest mac
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // src mac
        0x08, 0x00, // EtherType = 0x0800 (IPv4)
        'h', 'e', 'l', 'l', 'o', // payload
    };

    const frame = try ethernet.parse(&data);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E }, &frame.dest_mac);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, &frame.src_mac);
    try std.testing.expectEqual(ethernet.EtherType.ipv4, frame.ether_type);
    try std.testing.expectEqualStrings("hello", frame.payload);
}

test "parse rejects a frame shorter than the fixed header" {
    const data = [_]u8{0xFF} ** 13; // one byte short of the 14-byte header
    try std.testing.expectError(error.FrameTooShort, ethernet.parse(&data));
}

test "parse accepts a frame with an empty payload" {
    const data = [_]u8{0xFF} ** 14; // exactly the header, nothing after
    const frame = try ethernet.parse(&data);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

test "parse reads EtherType as big-endian, not little-endian" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x86;
    data[13] = 0xDD; // 0x86DD = IPv6

    const frame = try ethernet.parse(&data);

    // If readInt used the wrong endianness here, this would come out
    // as EtherType 0xDD86 (unnamed) instead of the named .ipv6 variant.
    try std.testing.expectEqual(ethernet.EtherType.ipv6, frame.ether_type);
}

test "parse's MAC fields are independent copies; payload still borrows" {
    var data = [_]u8{
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0x08, 0x00, 'x',  'y',  'z',
    };

    const frame = try ethernet.parse(&data);

    data[0] = 0xFF; // touches dest_mac's source bytes
    data[14] = 'Q'; // touches payload's source bytes

    try std.testing.expectEqual(@as(u8, 0xAA), frame.dest_mac[0]);
    try std.testing.expectEqual(@as(u8, 'Q'), frame.payload[0]);
}

test "parse maps an unrecognized EtherType to the non-exhaustive tag, not an error" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x12;
    data[13] = 0x34; // 0x1234 — not one of ipv4/arp/ipv6/vlan

    const frame = try ethernet.parse(&data);

    // None of the named variants should match...
    try std.testing.expect(frame.ether_type != .ipv4);
    try std.testing.expect(frame.ether_type != .arp);
    try std.testing.expect(frame.ether_type != .ipv6);
    try std.testing.expect(frame.ether_type != .vlan);

    // ...but the underlying numeric value must still round-trip correctly.
    try std.testing.expectEqual(@as(u16, 0x1234), @intFromEnum(frame.ether_type));
}
