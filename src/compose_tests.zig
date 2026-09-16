const std = @import("std");
const ethernet = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");

test "a full Ethernet frame carrying an IPv4 packet parses end to end" {
    const data = [_]u8{
        // --- Ethernet header (14 bytes) ---
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dest mac
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // src mac
        0x08, 0x00, // EtherType = IPv4

        // --- IPv4 header (20 bytes) ---
        0x45, // version=4, ihl=5
        0x00, // dscp=0, ecn=0
        0x00, 0x19, // total_length = 25 (20 header + 5 payload)
        0x00, 0x01, // identification
        0x00, 0x00, // flags=0, fragment_offset=0
        0x40, // ttl = 64
        0x06, // protocol = 6 (TCP)
        0x00, 0x00, // checksum (unchecked here)
        192, 168, 1, 10, // source
        10,  0,   0,   1, // destination

        // --- Payload (5 bytes) ---
        'H', 'e', 'l', 'l',
        'o',
    };

    // Layer 1: Ethernet
    const frame = try ethernet.parse(&data);
    try std.testing.expectEqual(ethernet.EtherType.ipv4, frame.ether_type);

    // Layer 2: IPv4 — fed frame.payload, NOT the original `data`.
    // This is the actual composition point a real dispatcher would hit
    // right after checking frame.ether_type == .ipv4.
    const packet = try ipv4.parse(frame.payload);

    try std.testing.expectEqual(@as(u8, 20), packet.header_length);
    try std.testing.expectEqual(@as(u8, 6), packet.header.protocol);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &packet.source);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &packet.destination);
    try std.testing.expectEqualStrings("Hello", packet.payload);
}

test "a non-IPv4 frame should be skipped by a dispatcher, not fed to IPv4 parse" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x08;
    data[13] = 0x06; // EtherType = ARP

    const frame = try ethernet.parse(&data);

    // The point here isn't calling ipv4.parse — it's confirming a
    // dispatcher has what it needs to decide NOT to. Calling it anyway
    // on ARP bytes wouldn't be a bug in ipv4.zig; it'd be a bug in
    // whatever code skipped this check.
    try std.testing.expect(frame.ether_type != .ipv4);
}

test "the IPv4 payload is still a borrow two layers deep into the original buffer" {
    var data = [_]u8{
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x19,
        0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
        0x00, 0x00, 192,  168,  1,    10,
        10,   0,    0,    1,    'H',  'e',
        'l',  'l',  'o',
    };

    const frame = try ethernet.parse(&data);
    const packet = try ipv4.parse(frame.payload);

    // Mutate the ORIGINAL buffer, two layers removed from `packet`.
    data[34] = 'X'; // the 'H' in "Hello"

    // If either layer had accidentally copied instead of borrowed, this
    // wouldn't show up. Since both layers deliberately borrow, it does.
    try std.testing.expectEqual(@as(u8, 'X'), packet.payload[0]);
}
