const std = @import("std");
const ethernet = @import("ethernet.zig");

test "parseEthernet parses all fields of a well-formed frame" {
    const data = [_]u8{
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dest mac
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // src mac
        0x08, 0x00, // EtherType = 0x0800 (IPv4)
        'h', 'e', 'l', 'l', 'o', // payload
    };

    const frame = try ethernet.parseEthernet(&data);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E }, &frame.dest_mac);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, &frame.src_mac);
    try std.testing.expectEqual(@as(u16, 0x0800), frame.ether_type);
    try std.testing.expectEqualStrings("hello", frame.payload);
}

test "parseEthernet rejects a frame shorter than the fixed header" {
    const data = [_]u8{0xFF} ** 13; // one byte short of the 14-byte header
    try std.testing.expectError(error.FrameTooShort, ethernet.parseEthernet(&data));
}

test "parseEthernet accepts a frame with an empty payload" {
    const data = [_]u8{0xFF} ** 14; // exactly the header, nothing after
    const frame = try ethernet.parseEthernet(&data);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

test "parseEthernet reads EtherType as big-endian, not little-endian" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x86;
    data[13] = 0xDD; // 0x86DD = IPv6

    const frame = try ethernet.parseEthernet(&data);

    // If readInt used the wrong endianness here, this would come out as
    // 0xDD86 instead — a real, easy-to-make mistake on wire formats.
    try std.testing.expectEqual(@as(u16, 0x86DD), frame.ether_type);
}

test "parseEthernet's MAC fields are independent copies; payload still borrows" {
    var data = [_]u8{
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0x08, 0x00, 'x',  'y',  'z',
    };

    const frame = try ethernet.parseEthernet(&data);

    // Mutate the original buffer after parsing.
    data[0] = 0xFF; // touches dest_mac's source bytes
    data[14] = 'Q'; // touches payload's source bytes

    // dest_mac was copied by value ([6]u8 via `.*`) — unaffected.
    try std.testing.expectEqual(@as(u8, 0xAA), frame.dest_mac[0]);

    // payload is a borrowed slice into `data` — the mutation shows through.
    try std.testing.expectEqual(@as(u8, 'Q'), frame.payload[0]);
}
