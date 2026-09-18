const ipv4 = @import("ipv4.zig");
const ethernet = @import("ethernet.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");

pub const ParsedPacket = struct {
    ethernet: ethernet.EthernetFrame,
    network: NetworkProtocol,
};

pub const NetworkProtocol = union(enum) {
    ipv4: IPv4Layer,
    unknown: u16,
};

pub const IPv4Layer = struct {
    packet: ipv4.IPv4Packet,
    transport: TransportProtocol,
};

pub const TransportProtocol = union(enum) {
    tcp: tcp.TcpSegment,
    udp: udp.UdpDatagram,
    unknown: u8,
};

pub fn parse(data: []const u8) !ParsedPacket {
    const eth = try ethernet.parse(data);

    const network = switch (eth.ether_type) {
        .ipv4 => blk: {
            const ip = try ipv4.parse(eth.payload);
            const transport = switch (ip.header.protocol) {
                6 => TransportProtocol{ .tcp = try tcp.parse(ip.payload) },
                17 => TransportProtocol{ .udp = try udp.parse(ip.payload) },
                else => TransportProtocol{ .unknown = ip.header.protocol },
            };
            break :blk NetworkProtocol{
                .ipv4 = .{ .packet = ip, .transport = transport },
            };
        },
        else => NetworkProtocol{ .unknown = @intFromEnum(eth.ether_type) },
    };

    return ParsedPacket{ .ethernet = eth, .network = network };
}
