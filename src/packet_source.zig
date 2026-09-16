const std = @import("std");
const packet = @import("packet.zig");
const Packet = packet.Packet;

pub const FakePacketSource = struct {
    allocator: std.mem.Allocator,
    fixtures: []const []const u8,
    index: usize,

    pub fn init(allocator: std.mem.Allocator, fixtures: []const []const u8) FakePacketSource {
        return .{ .allocator = allocator, .fixtures = fixtures, .index = 0 };
    }
    pub fn next(self: *FakePacketSource, io_init: std.Io) !Packet {
        if (self.index >= self.fixtures.len) return error.EndOfStream;

        const data = try self.allocator.dupe(u8, self.fixtures[self.index]);
        self.index += 1;

        const ts = std.Io.Clock.real.now(io_init);

        return Packet{
            .timestamp_ns = ts.toNanoseconds(),
            .data = data,
        };
    }
    pub fn deinit(_: *FakePacketSource) void {
        // FakePacketSource doesn't own `packets` (caller does) and
        // allocates nothing of its own beyond what `next()` hands out —
        // so nothing to free here yet. Kept as a real method anyway so
        // callers can always call `source.deinit()` uniformly, since
        // LinuxPacketSource almost certainly will need to close a
        // socket/fd here.
    }
};
