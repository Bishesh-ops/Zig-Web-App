const std = @import("std");

pub const TCPFlags = packed struct(u16) {
    // ---- Wire byte 12 (low byte of the u16) ----
    ns: bool, // bit 0  — LSB of byte 12
    reserved: u3, // bits 1-3
    data_offset: u4, // bits 4-7 — MSB of byte 12

    // ---- Wire byte 13 (high byte of the u16) ----
    fin: bool, // bit 8  — LSB of byte 13
    syn: bool, // bit 9
    rst: bool, // bit 10
    psh: bool, // bit 11
    ack: bool, // bit 12
    urg: bool, // bit 13
    ece: bool, // bit 14
    cwr: bool, // bit 15 — MSB of byte 13
};

pub const TCPHeader = packed struct(u160) {
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: TCPFlags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
};

pub const TcpSegment = struct {
    header: TCPHeader,
    header_length: u8,
    options: []const u8,
    payload: []const u8,
};

pub const ParseError = error{
    SegmentTooShort,
    InvalidHeaderLength,
};

pub fn parse(data: []const u8) ParseError!TcpSegment {
    if (data.len < 20) return error.SegmentTooShort;

    var base: TCPHeader = @bitCast(data[0..20].*);

    base.src_port = std.mem.bigToNative(u16, base.src_port);
    base.dest_port = std.mem.bigToNative(u16, base.dest_port);
    base.seq_num = std.mem.bigToNative(u32, base.seq_num);
    base.ack_num = std.mem.bigToNative(u32, base.ack_num);
    base.window_size = std.mem.bigToNative(u16, base.window_size);
    base.checksum = std.mem.bigToNative(u16, base.checksum);
    base.urgent_pointer = std.mem.bigToNative(u16, base.urgent_pointer);

    const header_bytes = @as(u8, base.flags.data_offset) * 4;
    if (header_bytes < 20) return error.InvalidHeaderLength;
    if (data.len < header_bytes) return error.SegmentTooShort;

    return TcpSegment{
        .header = base,
        .header_length = header_bytes,
        .options = data[20..header_bytes],
        .payload = data[header_bytes..],
    };
}
