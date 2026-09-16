const std = @import("std");
const app = @import("app"); // Imports the module we defined in build.zig
const ethernet = app.ethernet;
const parser = app.parser;

test "parse recognizes an IPv4 frame and parses the network layer" {
    const data = [_]u8{
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dest mac
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // src mac
        0x08, 0x00, // EtherType = IPv4

        // --- IPv4 header (20 bytes) ---
        0x45, 0x00,
        0x00, 0x19, // total_length = 25 (20 header + 5 payload)
        0x00, 0x01,
        0x00, 0x00,
        0x40, // ttl
        0x06, // protocol = TCP
        0x00,
        0x00,
        192,
        168,
        1,
        10,
        10,
        0,
        0,
        1,

        // --- Payload (5 bytes) ---
        'H',
        'e',
        'l',
        'l',
        'o',
    };

    const packet = try parser.parse(&data);

    try std.testing.expectEqual(ethernet.EtherType.ipv4, packet.ethernet.ether_type);

    switch (packet.network) {
        .ipv4 => |ip| {
            try std.testing.expectEqual(@as(u8, 6), ip.header.protocol);
            try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &ip.source);
            try std.testing.expectEqualStrings("Hello", ip.payload);
        },
        .unknown => return error.TestUnexpectedResult,
    }
}

test "parse falls back to unknown for a non-IPv4 EtherType, carrying the raw value" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x08;
    data[13] = 0x06; // EtherType = ARP (0x0806) — not handled by the switch

    const packet = try parser.parse(&data);

    try std.testing.expectEqual(ethernet.EtherType.arp, packet.ethernet.ether_type);

    switch (packet.network) {
        .unknown => |raw| try std.testing.expectEqual(@as(u16, 0x0806), raw),
        .ipv4 => return error.TestUnexpectedResult,
    }
}

test "parse falls back to unknown for a genuinely unregistered EtherType too" {
    // Not just "any non-IPv4 case" — this is a value with no named
    // EtherType variant at all, exercising the non-exhaustive `_` tag
    // flowing all the way through the dispatcher's `else` branch.
    var data = [_]u8{0} ** 14;
    data[12] = 0x12;
    data[13] = 0x34;

    const packet = try parser.parse(&data);

    switch (packet.network) {
        .unknown => |raw| try std.testing.expectEqual(@as(u16, 0x1234), raw),
        .ipv4 => return error.TestUnexpectedResult,
    }
}

test "parse surfaces an Ethernet-layer error without touching IPv4 at all" {
    const data = [_]u8{0xFF} ** 13; // one byte short of a valid Ethernet header
    try std.testing.expectError(error.FrameTooShort, parser.parse(&data));
}

test "parse surfaces an IPv4-layer error through the dispatcher" {
    var data = [_]u8{0} ** 14;
    data[12] = 0x08;
    data[13] = 0x00; // EtherType = IPv4, but there's no IPv4 header at all in payload

    try std.testing.expectError(
        error.PacketTooShort,
        parser.parse(&data),
    );
}
