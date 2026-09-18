// test/root.zig
test {
    _ = @import("fixtures.zig");
    _ = @import("test_tcp.zig");
    _ = @import("test_stack.zig");
    _ = @import("test_ethernet.zig");
    _ = @import("test_http.zig");
    _ = @import("test_ipv4.zig");
    _ = @import("test_udp.zig");
}
