const std = @import("std");

/// Represents the mandatory 20-byte base fields of an IPv4 header.
/// `source`/`destination` live outside this packed struct — Zig packed
/// structs can't contain array fields, so the two 4-byte addresses are
/// extracted separately in `parse` and carried on `ParsedPacket` instead.
///
/// Zig packs fields from LSB to MSB within the backing integer, which is
/// why sub-byte fields (version/ihl, dscp/ecn, flags/fragment_offset)
/// are declared in the reverse order you'd read them on the wire.
pub const IPv4BaseHeader = packed struct(u96) {
    ihl: u4,
    version: u4,

    ecn: u2,
    dscp: u6,

    total_length: u16,

    identification: u16,

    fragment_offset: u13,
    flags: u3,

    ttl: u8,

    protocol: u8,

    checksum: u16,

    pub const ParseError = error{
        PacketTooShort,
        InvalidVersion,
        InvalidHeaderLength,
        TotalLengthMismatch,
    };

    /// Safely handles byte-swapping and extracts any variable options/payload data.
    pub fn parse(data: []const u8) ParseError!ParsedPacket {
        if (data.len < 20) return ParseError.PacketTooShort;

        var base: IPv4BaseHeader = @bitCast(data[0..12].*);

        if (base.version != 4) return ParseError.InvalidVersion;

        base.total_length = std.mem.bigToNative(u16, base.total_length);
        base.identification = std.mem.bigToNative(u16, base.identification);
        base.checksum = std.mem.bigToNative(u16, base.checksum);

        const raw_flags_offset = std.mem.readInt(u16, data[6..8], .big);
        base.flags = @truncate(raw_flags_offset >> 13);
        base.fragment_offset = @truncate(raw_flags_offset & 0x1FFF);

        const header_bytes = @as(u8, base.ihl) * 4;
        if (header_bytes < 20) return ParseError.InvalidHeaderLength;
        if (data.len < header_bytes) return ParseError.PacketTooShort;
        if (base.total_length < header_bytes) return ParseError.TotalLengthMismatch;
        if (data.len < base.total_length) return ParseError.TotalLengthMismatch;

        return ParsedPacket{
            .header = base,
            .header_length = header_bytes,
            .source = data[12..16].*,
            .destination = data[16..20].*,
            .options = data[20..header_bytes],
            .payload = data[header_bytes..base.total_length],
        };
    }
};

pub const ParsedPacket = struct {
    header: IPv4BaseHeader,
    header_length: u8,
    source: [4]u8,
    destination: [4]u8,
    options: []const u8,
    payload: []const u8,
};
