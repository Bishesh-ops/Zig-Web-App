const std = @import("std");
const http = @import("http.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const IP = "127.0.0.1";
    const PORT: i32 = 7070;

    var address = try std.Io.net.IpAddress.parse(IP, PORT);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);

    std.debug.print("PacketScope listening on {s}:{d}\n", .{ IP, PORT });

    while (true) {
        var connection = try listener.accept(io);
        defer connection.close(io);

        var reader_buffer: [4096]u8 = undefined;
        var reader = connection.reader(io, &reader_buffer);

        const request = http.readRequest(&reader.interface, gpa) catch |err| {
            std.debug.print("failed to parse request: {}\n", .{err});
            continue;
        };
        defer request.deinit(gpa);

        std.debug.print(
            \\--- Incoming Request ---
            \\{s} {s} {s}
            \\
        , .{
            @tagName(request.request_line.method),
            request.request_line.path,
            @tagName(request.request_line.version),
        });

        if (request.headers.len == 0) {
            std.debug.print("(no headers)\n", .{});
        } else {
            for (request.headers) |header| {
                std.debug.print("  {s}: {s}\n", .{ header.name, header.value });
            }
        }

        if (request.body) |body| {
            std.debug.print("Body ({d} bytes): {s}\n", .{ body.len, body[0..@min(body.len, 80)] });
        } else {
            std.debug.print("(no body)\n", .{});
        }
        std.debug.print("-------------------------\n", .{});

        var response_buffer: [4096]u8 = undefined;
        var response_impl = connection.writer(io, &response_buffer);
        var response = &response_impl.interface;
        const body = "Hello From PacketScope!\n";
        try response.print(
            "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "Content-Length: {}\r\n" ++
                "Connection: close\r\n" ++
                "\r\n" ++
                "{s}",
            .{ body.len, body },
        );

        try response.flush();
    }
}
