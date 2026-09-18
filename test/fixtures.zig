// test/fixtures.zig
const std = @import("std");

/// A minimal valid TCP SYN segment, 20-byte header, no payload.
/// src_port=49451, dst_port=80, seq=1, ack=0, flags=SYN, window=65535.
pub const tcp_syn_20 = [_]u8{
    0xC1, 0x2B, // src_port = 49451
    0x00, 0x50, // dst_port = 80
    0x00, 0x00, 0x00, 0x01, // seq_num = 1
    0x00, 0x00, 0x00, 0x00, // ack_num = 0
    0x50, 0x02, // data_offset=5, SYN
    0xFF, 0xFF, // window_size = 65535
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent_pointer
};

/// A TCP segment with 4 bytes of TCP options (data_offset = 6 / 24 bytes).
pub const tcp_with_options = [_]u8{
    0xC1, 0x2B, // src_port
    0x00, 0x50, // dst_port
    0x00, 0x00, 0x00, 0x01, // seq
    0x00, 0x00, 0x00, 0x00, // ack
    0x60, 0x02, // data_offset=6 (24 bytes), SYN
    0xFF, 0xFF, // window
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent
    0x02, 0x04, 0x05, 0xB4, // MSS option (kind=2, len=4, mss=1460)
};

/// A TCP segment with an 8-byte payload ("Hi there").
pub const tcp_with_payload = [_]u8{
    0xC1, 0x2B, // src_port
    0x00, 0x50, // dst_port
    0x00, 0x00, 0x00, 0x01, // seq
    0x00, 0x00, 0x00, 0x01, // ack
    0x50, 0x18, // data_offset=5, PSH+ACK
    0xFF, 0xFF, // window
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent
    'H',  'i',
    ' ',  't',
    'h',  'e',
    'r',  'e',
};

/// Full TCP segment with every flag bit set — useful for verifying bit order.
/// data_offset=5, flags byte = 0xFF (all flags), reserved = 0.
pub const tcp_all_flags = [_]u8{
    0xC1, 0x2B, 0x00, 0x50,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0xFF, // all 8 low flags set, NS = 0
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

// ---------- Helper builders for integration tests ----------

/// Writes a 14-byte Ethernet header into `buf` and returns the slice.
pub fn buildEthernetHeader(
    buf: []u8,
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16,
) []u8 {
    @memcpy(buf[0..6], &dest_mac);
    @memcpy(buf[6..12], &src_mac);
    std.mem.writeInt(u16, buf[12..14], ether_type, .big);
    return buf[0..14];
}

/// Builds a 20-byte IPv4 header (no options) into `buf`.
pub fn buildIPv4Header(
    buf: []u8,
    src: [4]u8,
    dst: [4]u8,
    protocol: u8,
    payload_len: u16,
) []u8 {
    const total_len: u16 = 20 + payload_len;
    buf[0] = 0x45; // version=4, ihl=5
    buf[1] = 0x00; // dscp/ecn
    std.mem.writeInt(u16, buf[2..4], total_len, .big);
    std.mem.writeInt(u16, buf[4..6], 0, .big); // identification
    std.mem.writeInt(u16, buf[6..8], 0x4000, .big); // don't fragment
    buf[8] = 64; // ttl
    buf[9] = protocol;
    std.mem.writeInt(u16, buf[10..12], 0, .big); // checksum
    @memcpy(buf[12..16], &src);
    @memcpy(buf[16..20], &dst);
    return buf[0..20];
}

/// Minimal UDP datagram: 8-byte header, no payload.
/// src_port=53, dst_port=53000, length=8, checksum=0.
pub const udp_empty = [_]u8{
    0x00, 0x35, // src_port = 53
    0xCF, 0x08, // dst_port = 53000
    0x00, 0x08, // length = 8
    0x00, 0x00, // checksum (0 = not computed; legal in IPv4)
};

/// UDP datagram carrying a 4-byte ASCII payload ("PING").
/// length = 12 (8 header + 4 payload).
pub const udp_with_payload = [_]u8{
    0x00, 0x35,
    0xCF, 0x08,
    0x00, 0x0C, // length = 12
    0x00, 0x00,
    'P',  'I',
    'N',  'G',
};

/// Same as `udp_with_payload`, but with 4 bytes of Ethernet-style
/// padding appended. `length` still says 12, buffer is 16.
pub const udp_padded = [_]u8{
    0x00, 0x35,
    0xCF, 0x08,
    0x00, 0x0C,
    0x00, 0x00,
    'P',  'I',
    'N',  'G',
    0xAA, 0xAA,
    0xAA, 0xAA,
};
