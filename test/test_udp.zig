const std = @import("std");
const testing = std.testing;

const app = @import("app");
const udp = app.udp;
const fixtures = @import("fixtures.zig");

test "UDP: parses minimal 8-byte header" {
    const dg = try udp.parse(&fixtures.udp_empty);

    try testing.expectEqual(@as(u16, 53), dg.header.src_port);
    try testing.expectEqual(@as(u16, 53000), dg.header.dest_port);
    try testing.expectEqual(@as(u16, 8), dg.header.length);
    try testing.expectEqual(@as(u16, 0), dg.header.checksum);
    try testing.expectEqual(@as(usize, 0), dg.payload.len);
}

test "UDP: payload is sliced to the declared length" {
    const dg = try udp.parse(&fixtures.udp_with_payload);

    try testing.expectEqual(@as(u16, 12), dg.header.length);
    try testing.expectEqual(@as(usize, 4), dg.payload.len);
    try testing.expectEqualSlices(u8, "PING", dg.payload);
}

test "UDP: trailing buffer padding is excluded from payload" {
    const dg = try udp.parse(&fixtures.udp_padded);

    // Buffer has 16 bytes; length says 12. Payload must be 4, not 8.
    try testing.expectEqual(@as(usize, 4), dg.payload.len);
    try testing.expectEqualSlices(u8, "PING", dg.payload);
}

test "UDP: payload is a zero-copy borrow" {
    var buf = fixtures.udp_with_payload;
    const dg = try udp.parse(&buf);

    buf[8] = 'X';
    try testing.expectEqual(@as(u8, 'X'), dg.payload[0]);
}

test "UDP: rejects buffers shorter than 8 bytes" {
    try testing.expectError(error.DatagramTooShort, udp.parse(&[_]u8{0} ** 7));
    try testing.expectError(error.DatagramTooShort, udp.parse(&[_]u8{}));
}

test "UDP: rejects declared length < 8 (InvalidLength)" {
    var buf = fixtures.udp_empty;
    buf[4] = 0x00;
    buf[5] = 0x04; // length = 4
    try testing.expectError(error.InvalidLength, udp.parse(&buf));
}

test "UDP: rejects declared length exceeding buffer" {
    var buf = fixtures.udp_empty;
    buf[4] = 0x00;
    buf[5] = 0xFF; // claims 255 bytes; buffer is 8
    try testing.expectError(error.LengthExceedsBuffer, udp.parse(&buf));
}

test "UDP: multi-byte fields are big-endian on the wire" {
    var buf = fixtures.udp_empty;
    buf[0] = 0x12;
    buf[1] = 0x34;
    const dg = try udp.parse(&buf);
    try testing.expectEqual(@as(u16, 0x1234), dg.header.src_port);
}
