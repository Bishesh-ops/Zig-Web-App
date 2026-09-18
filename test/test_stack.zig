// test/test_stack.zig
const std = @import("std");
const testing = std.testing;

const app = @import("app");
const parser = app.parser;
const fixtures = @import("fixtures.zig");

// ---------------------------------------------------------------------------
// A tiny helper that turns a byte slice into a std.Io.Reader.
//
// The exact constructor for a "fixed" (slice-backed) reader has moved around
// between 0.15 and 0.16. Right now it's `std.Io.Reader.fixed(data)`. If a
// future nightly renames it, you only have to update this one function.
// ---------------------------------------------------------------------------
fn sliceReader(data: []const u8) std.Io.Reader {
    return std.Io.Reader.fixed(data);
}

// ---------------------------------------------------------------------------
// Constants used by every integration test
// ---------------------------------------------------------------------------
const TEST_SRC_IP = [4]u8{ 192, 168, 1, 100 };
const TEST_DST_IP = [4]u8{ 192, 168, 1, 1 };
const TEST_SRC_MAC = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
const TEST_DST_MAC = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02 };

// ---------------------------------------------------------------------------
// Frame builder
// ---------------------------------------------------------------------------

/// Assembles a full Ethernet + IPv4 + <transport> frame into `buf` and
/// returns the used prefix as an explicit `[]u8` slice.
///
/// `ip_protocol` is the IANA protocol number that goes in the IPv4 header:
///   6  = TCP
///   17 = UDP
fn buildFrame(buf: []u8, ip_protocol: u8, transport_bytes: []const u8) []u8 {
    var offset: usize = 0;

    const eth_region: []u8 = buf[offset..];
    _ = fixtures.buildEthernetHeader(eth_region, TEST_DST_MAC, TEST_SRC_MAC, 0x0800);
    offset += 14;

    const ip_region: []u8 = buf[offset..];
    _ = fixtures.buildIPv4Header(
        ip_region,
        TEST_SRC_IP,
        TEST_DST_IP,
        ip_protocol,
        @intCast(transport_bytes.len),
    );
    offset += 20;

    const payload_region: []u8 = buf[offset..];
    @memcpy(payload_region[0..transport_bytes.len], transport_bytes);
    offset += transport_bytes.len;

    return buf[0..offset];
}

// ---------------------------------------------------------------------------
// TCP integration tests
// ---------------------------------------------------------------------------

test "Stack: Ethernet -> IPv4 -> TCP with SYN segment" {
    var buf: [128]u8 = undefined;
    const frame = buildFrame(&buf, 6, &fixtures.tcp_syn_20);

    const parsed = try parser.parse(frame);

    // --- Ethernet ---
    try testing.expectEqual(app.ethernet.EtherType.ipv4, parsed.ethernet.ether_type);
    try testing.expectEqualSlices(u8, &TEST_SRC_MAC, &parsed.ethernet.src_mac);
    try testing.expectEqualSlices(u8, &TEST_DST_MAC, &parsed.ethernet.dest_mac);

    // --- IPv4 ---
    const ip_layer = parsed.network.ipv4;
    try testing.expectEqualSlices(u8, &TEST_SRC_IP, &ip_layer.packet.source);
    try testing.expectEqualSlices(u8, &TEST_DST_IP, &ip_layer.packet.destination);
    try testing.expectEqual(@as(u8, 6), ip_layer.packet.header.protocol);
    try testing.expectEqual(@as(u4, 4), ip_layer.packet.header.version);

    // --- TCP ---
    const seg = ip_layer.transport.tcp;
    try testing.expectEqual(@as(u16, 49451), seg.header.src_port);
    try testing.expectEqual(@as(u16, 80), seg.header.dest_port);
    try testing.expect(seg.header.flags.syn);
    try testing.expect(!seg.header.flags.ack);
    try testing.expect(!seg.header.flags.fin);
    try testing.expectEqual(@as(u4, 5), seg.header.flags.data_offset);
}

test "Stack: TCP payload slices all the way back to the frame buffer" {
    var buf: [256]u8 = undefined;
    const frame = buildFrame(&buf, 6, &fixtures.tcp_with_payload);

    const parsed = try parser.parse(frame);
    const seg = parsed.network.ipv4.transport.tcp;

    try testing.expectEqualSlices(u8, "Hi there", seg.payload);

    // Locate the payload start inside the original frame: 14 (eth) + 20 (ip) + 20 (tcp).
    const payload_start = 14 + 20 + 20;
    buf[payload_start] = 'X';
    try testing.expectEqual(@as(u8, 'X'), seg.payload[0]);
}

test "Stack: TCP options are exposed when data_offset > 5" {
    var buf: [256]u8 = undefined;
    const frame = buildFrame(&buf, 6, &fixtures.tcp_with_options);

    const parsed = try parser.parse(frame);
    const seg = parsed.network.ipv4.transport.tcp;

    try testing.expectEqual(@as(u4, 6), seg.header.flags.data_offset);
    try testing.expectEqual(@as(u8, 24), seg.header_length);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x04, 0x05, 0xB4 }, seg.options);
    try testing.expectEqual(@as(usize, 0), seg.payload.len);
}

// ---------------------------------------------------------------------------
// Dispatch / branching tests
// ---------------------------------------------------------------------------

test "Stack: non-IPv4 EtherType short-circuits network parsing" {
    var buf: [128]u8 = undefined;
    const eth_region: []u8 = buf[0..];
    _ = fixtures.buildEthernetHeader(eth_region, TEST_DST_MAC, TEST_SRC_MAC, 0x0806); // ARP

    const parsed = try parser.parse(buf[0..14]);

    switch (parsed.network) {
        .unknown => |et| try testing.expectEqual(@as(u16, 0x0806), et),
        .ipv4 => return error.TestUnexpectedIpv4,
    }
}

test "Stack: UDP dispatch fires only for IP protocol 17" {
    var buf: [128]u8 = undefined;
    const frame = buildFrame(&buf, 6, &fixtures.tcp_syn_20);

    const parsed = try parser.parse(frame);

    switch (parsed.network.ipv4.transport) {
        .udp => return error.TestUnexpectedUdp,
        .tcp => {}, // expected: protocol 6 dispatched to TCP
        .unknown => return error.TestUnexpectedUnknown,
    }
}

// ---------------------------------------------------------------------------
// UDP integration tests
// ---------------------------------------------------------------------------

test "Stack: Ethernet -> IPv4 -> UDP with a small datagram" {
    var buf: [128]u8 = undefined;
    const frame = buildFrame(&buf, 17, &fixtures.udp_with_payload);

    const parsed = try parser.parse(frame);
    const ip_layer = parsed.network.ipv4;

    try testing.expectEqual(@as(u8, 17), ip_layer.packet.header.protocol);

    const dg = ip_layer.transport.udp;
    try testing.expectEqual(@as(u16, 53), dg.header.src_port);
    try testing.expectEqual(@as(u16, 53000), dg.header.dest_port);
    try testing.expectEqualSlices(u8, "PING", dg.payload);
}

test "Stack: UDP payload slices all the way back to the frame buffer" {
    var buf: [256]u8 = undefined;
    const frame = buildFrame(&buf, 17, &fixtures.udp_with_payload);

    const parsed = try parser.parse(frame);
    const dg = parsed.network.ipv4.transport.udp;
    try testing.expectEqualSlices(u8, "PING", dg.payload);

    // UDP payload starts at 14 (eth) + 20 (ip) + 8 (udp header) = 42.
    frame[42] = 'X';
    try testing.expectEqual(@as(u8, 'X'), dg.payload[0]);
}

// ---------------------------------------------------------------------------
// Full pipeline: Ethernet -> IPv4 -> TCP -> HTTP
// ---------------------------------------------------------------------------

test "Stack: full HTTP-over-TCP request parses end-to-end" {
    const http_payload =
        "GET /hello HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: zig-test\r\n" ++
        "\r\n";

    // Build a TCP segment with data_offset = 5 (no options) carrying the HTTP payload.
    var tcp_bytes: [512]u8 = undefined;
    @memcpy(tcp_bytes[0..20], &[_]u8{
        0xC1, 0x2B, // src_port = 49451
        0x00, 0x50, // dst_port = 80
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x01, // ack
        0x50, 0x18, // data_offset = 5, PSH + ACK
        0xFF, 0xFF, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent pointer
    });
    @memcpy(tcp_bytes[20..][0..http_payload.len], http_payload);
    const tcp_slice = tcp_bytes[0 .. 20 + http_payload.len];

    var frame_buf: [1024]u8 = undefined;
    const frame = buildFrame(&frame_buf, 6, tcp_slice);

    // Walk the stack.
    const parsed = try parser.parse(frame);
    const seg = parsed.network.ipv4.transport.tcp;
    try testing.expectEqual(@as(usize, http_payload.len), seg.payload.len);
    try testing.expect(seg.header.flags.psh);
    try testing.expect(seg.header.flags.ack);
    try testing.expect(!seg.header.flags.syn);

    // Feed the TCP payload into the HTTP parser via a slice-backed reader.
    var reader = sliceReader(seg.payload);
    const req = try app.http.readRequest(&reader, testing.allocator);
    defer req.deinit(testing.allocator);

    try testing.expectEqual(app.http.Method.GET, req.request_line.method);
    try testing.expectEqualStrings("/hello", req.request_line.path);
    try testing.expectEqual(app.http.Version.http_1_1, req.request_line.version);
    try testing.expectEqual(@as(usize, 2), req.headers.len);
    try testing.expectEqualStrings("Host", req.headers[0].name);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
    try testing.expectEqualStrings("User-Agent", req.headers[1].name);
    try testing.expectEqualStrings("zig-test", req.headers[1].value);
    try testing.expect(req.body == null);
}
