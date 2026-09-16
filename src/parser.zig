const ipv4 = @import("ipv4.zig");
const ethernet = @import("ethernet.zig");

pub const ParsedPacket = struct {
    ethernet: ethernet.EthernetFrame,
    network: NetworkProtocol,
};

pub const NetworkProtocol = union(enum) {
    ipv4: ipv4.IPv4Packet,
    unknown: u16,
};

pub fn parse(data: []const u8) !ParsedPacket {
    const eth = try ethernet.parse(data);

    const network = switch (eth.ether_type) {
        .ipv4 => NetworkProtocol{
            .ipv4 = try ipv4.parse(eth.payload),
        },

        else => NetworkProtocol{
            .unknown = @intFromEnum(eth.ether_type),
        },
    };

    return ParsedPacket{
        .ethernet = eth,
        .network = network,
    };
}
