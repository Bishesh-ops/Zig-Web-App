const std = @import("std");

pub const Packet = struct {
    timestamp_ns: i128,
    data: []const u8,

    pub fn deinit(self: Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};
