const std = @import("std");
const testing = std.testing;

const app = @import("app");
const tcp = app.tcp;
const fixtures = @import("fixtures.zig");

test "TCP: parses minimal 20-byte header fields" {
    const seg = try tcp.parse(&fixtures.tcp_syn_20);

    try testing.expectEqual(@as(u16, 49451), seg.header.src_port);
    try testing.expectEqual(@as(u16, 80), seg.header.dest_port);
    try testing.expectEqual(@as(u32, 1), seg.header.seq_num);
    try testing.expectEqual(@as(u32, 0), seg.header.ack_num);
    try testing.expectEqual(@as(u16, 65535), seg.header.window_size);
    try testing.expectEqual(@as(u16, 0), seg.header.checksum);
    try testing.expectEqual(@as(u16, 0), seg.header.urgent_pointer);
}

test "TCP: data_offset and header_length match on a bare segment" {
    const seg = try tcp.parse(&fixtures.tcp_syn_20);

    try testing.expectEqual(@as(u4, 5), seg.header.flags.data_offset);
    try testing.expectEqual(@as(u8, 20), seg.header_length);
    try testing.expectEqual(@as(usize, 0), seg.options.len);
    try testing.expectEqual(@as(usize, 0), seg.payload.len);
}

test "TCP: SYN flag is set, others clear (verifies LSB-first bit layout)" {
    const seg = try tcp.parse(&fixtures.tcp_syn_20);

    try testing.expect(seg.header.flags.syn);
    try testing.expect(!seg.header.flags.ack);
    try testing.expect(!seg.header.flags.fin);
    try testing.expect(!seg.header.flags.rst);
    try testing.expect(!seg.header.flags.psh);
    try testing.expect(!seg.header.flags.urg);
    try testing.expect(!seg.header.flags.ece);
    try testing.expect(!seg.header.flags.cwr);
    try testing.expect(!seg.header.flags.ns);
}

test "TCP: PSH+ACK flags parse correctly" {
    const seg = try tcp.parse(&fixtures.tcp_with_payload);

    try testing.expect(seg.header.flags.psh);
    try testing.expect(seg.header.flags.ack);
    try testing.expect(!seg.header.flags.syn);
    try testing.expect(!seg.header.flags.fin);
}

test "TCP: every flag bit parses independently (0xFF flag byte)" {
    const seg = try tcp.parse(&fixtures.tcp_all_flags);

    // data_offset must still be 5 (upper nibble of byte 12)
    try testing.expectEqual(@as(u4, 5), seg.header.flags.data_offset);
    // All 8 low-byte flags are set
    try testing.expect(seg.header.flags.cwr);
    try testing.expect(seg.header.flags.ece);
    try testing.expect(seg.header.flags.urg);
    try testing.expect(seg.header.flags.ack);
    try testing.expect(seg.header.flags.psh);
    try testing.expect(seg.header.flags.rst);
    try testing.expect(seg.header.flags.syn);
    try testing.expect(seg.header.flags.fin);
    // NS is the LSB of byte 12 — it's 0 in this fixture
    try testing.expect(!seg.header.flags.ns);
}

test "TCP: options are sliced correctly when data_offset > 5" {
    const seg = try tcp.parse(&fixtures.tcp_with_options);

    try testing.expectEqual(@as(u4, 6), seg.header.flags.data_offset);
    try testing.expectEqual(@as(u4, 6), seg.header.flags.data_offset);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x04, 0x05, 0xB4 }, seg.options);
    try testing.expectEqual(@as(usize, 0), seg.payload.len);
}

test "TCP: payload is a slice past the header" {
    const seg = try tcp.parse(&fixtures.tcp_with_payload);

    try testing.expectEqual(@as(usize, 8), seg.payload.len);
    try testing.expectEqualSlices(u8, "Hi there", seg.payload);
    try testing.expectEqual(@as(usize, 0), seg.options.len);
}

test "TCP: payload slice aliases the source buffer (zero-copy)" {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..20], &fixtures.tcp_syn_20);
    @memcpy(buf[20..28], "PAYLOAD!");

    // Patch data_offset byte to still say "no options"
    buf[12] = 0x50;

    const seg = try tcp.parse(buf[0..28]);
    try testing.expectEqual(@as(usize, 8), seg.payload.len);

    // Mutating the source must be visible through the slice
    buf[20] = 'p';
    try testing.expectEqual(@as(u8, 'p'), seg.payload[0]);
}

// ---------- Error paths ----------

test "TCP: rejects a 19-byte buffer (SegmentTooShort)" {
    const too_short = fixtures.tcp_syn_20[0..19];
    try testing.expectError(error.SegmentTooShort, tcp.parse(too_short));
}

test "TCP: rejects an empty buffer" {
    try testing.expectError(error.SegmentTooShort, tcp.parse(&[_]u8{}));
}

test "TCP: rejects data_offset < 5 (InvalidHeaderLength)" {
    var buf = fixtures.tcp_syn_20;
    buf[12] = 0x40; // data_offset = 4
    try testing.expectError(error.InvalidHeaderLength, tcp.parse(&buf));
}

test "TCP: rejects data_offset beyond buffer length" {
    var buf = fixtures.tcp_syn_20;
    buf[12] = 0xF0; // data_offset = 15 -> 60 bytes, but buffer is 20
    try testing.expectError(error.SegmentTooShort, tcp.parse(&buf));
}

// ---------- Endianness ----------

test "TCP: multi-byte fields are big-endian on the wire" {
    // src_port = 0x1234 means bytes [0x12, 0x34] on the wire.
    var buf = fixtures.tcp_syn_20;
    buf[0] = 0x12;
    buf[1] = 0x34;
    const seg = try tcp.parse(&buf);
    try testing.expectEqual(@as(u16, 0x1234), seg.header.src_port);

    // Same for a 32-bit field: seq = 0xDEADBEEF
    buf[4] = 0xDE;
    buf[5] = 0xAD;
    buf[6] = 0xBE;
    buf[7] = 0xEF;
    const seg2 = try tcp.parse(&buf);
    try testing.expectEqual(@as(u32, 0xDEADBEEF), seg2.header.seq_num);
}
