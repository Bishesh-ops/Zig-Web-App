const std = @import("std");
const pkt = @import("packet.zig");
const fps = @import("packet_source.zig");

test "Packet owns its data independent of the source buffer" {
    var source = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const packet = pkt.Packet{
        .timestamp_ns = 0,
        .data = try std.testing.allocator.dupe(u8, &source),
    };
    defer packet.deinit(std.testing.allocator);

    source[0] = 0xFF;

    try std.testing.expectEqual(@as(u8, 0xAA), packet.data[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC, 0xDD }, packet.data);
}

test "Packet.deinit frees its data" {
    const packet = pkt.Packet{
        .timestamp_ns = 0,
        .data = try std.testing.allocator.dupe(u8, &.{ 1, 2, 3 }),
    };
    packet.deinit(std.testing.allocator);
}

test "FakePacketSource returns fixtures in order, each independently owned" {
    const fixture_a = [_]u8{ 1, 2, 3 };
    const fixture_b = [_]u8{ 4, 5 };

    var source = fps.FakePacketSource.init(std.testing.allocator, &.{ &fixture_a, &fixture_b });
    defer source.deinit();

    const first = try source.next(std.testing.io);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &fixture_a, first.data);

    const second = try source.next(std.testing.io);
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &fixture_b, second.data);
}

test "FakePacketSource packets are independent copies, not views into fixtures" {
    var fixture = [_]u8{ 0xAA, 0xBB };

    var source = fps.FakePacketSource.init(std.testing.allocator, &.{&fixture});
    defer source.deinit();

    const packt = try source.next(std.testing.io);
    defer packt.deinit(std.testing.allocator);

    fixture[0] = 0xFF;

    try std.testing.expectEqual(@as(u8, 0xAA), packt.data[0]);
}

test "FakePacketSource returns EndOfStream once fixtures are exhausted" {
    var source = fps.FakePacketSource.init(std.testing.allocator, &.{});
    defer source.deinit();

    try std.testing.expectError(error.EndOfStream, source.next(std.testing.io));
}

test "FakePacketSource stays exhausted on repeated calls" {
    const fixture = [_]u8{1};
    var source = fps.FakePacketSource.init(std.testing.allocator, &.{&fixture});
    defer source.deinit();

    const packt = try source.next(std.testing.io);
    packt.deinit(std.testing.allocator);

    try std.testing.expectError(error.EndOfStream, source.next(std.testing.io));
    try std.testing.expectError(error.EndOfStream, source.next(std.testing.io));
}
