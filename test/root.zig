// test/root.zig
test {
    _ = @import("compose_tests.zig");
    _ = @import("test_ethernet.zig");
    _ = @import("test_http.zig");
    _ = @import("test_ipv4.zig");
    _ = @import("test_packet_engine.zig");
    _ = @import("test_parser.zig");
}
