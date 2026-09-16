const std = @import("std");
const app = @import("app");
const http = app.http;

// Test Parsing Functions
test "parse GET RequestLine" {
    const request = try http.parseRequestLine("GET /api/user/profile HTTP/1.1\r\n");

    try std.testing.expectEqual(http.Method.GET, request.method);
    try std.testing.expectEqualStrings("/api/user/profile", request.path);
    try std.testing.expectEqual(http.Version.http_1_1, request.version);
}
test "parse POST RequestLine" {
    const request = try http.parseRequestLine("POST /api/user/update-status HTTP/1.0\r\n");

    try std.testing.expectEqual(http.Method.POST, request.method);
    try std.testing.expectEqualStrings("/api/user/update-status", request.path);
    try std.testing.expectEqual(http.Version.http_1_0, request.version);
}
test "parse DELETE RequestLine" {
    const request = try http.parseRequestLine("DELETE /api/admin/remove-users HTTP/1.1\r\n");

    try std.testing.expectEqual(http.Method.DELETE, request.method);
    try std.testing.expectEqualStrings("/api/admin/remove-users", request.path);
    try std.testing.expectEqual(http.Version.http_1_1, request.version);
}
test "parse PUTS RequestLine" {
    const request = try http.parseRequestLine("PUT /api/update-relations HTTP/1.0\r\n");

    try std.testing.expectEqual(http.Method.PUT, request.method);
    try std.testing.expectEqualStrings("/api/update-relations", request.path);
    try std.testing.expectEqual(http.Version.http_1_0, request.version);
}
// Test readRequestLine
test "readRequestLine parses a GET RequestLine line" {
    var reader: std.Io.Reader = .fixed("GET /api/user/profile HTTP/1.1\r\n");
    const request = try http.readRequestLine(&reader);

    try std.testing.expectEqualStrings("GET /api/user/profile HTTP/1.1", request);
}

test "readRequestLine still works without a trailing CRLF" {
    var reader: std.Io.Reader = .fixed("POST /api/update-status HTTP/1.0");
    const request = try http.readRequestLine(&reader);

    try std.testing.expectEqualStrings("POST /api/update-status HTTP/1.0", request);
}

test "readRequestLine surfaces a bad method as an error" {
    var reader: std.Io.Reader = .fixed("PATCH /api/thing HTTP/1.1\r\n");
    const line = try http.readRequestLine(&reader);
    try std.testing.expectError(error.InvalidMethod, http.parseRequestLine(line));
}

test "readRequestLine surfaces an empty RequestLine as an error" {
    var reader: std.Io.Reader = .fixed("\r\n");
    const line = try http.readRequestLine(&reader);
    try std.testing.expectError(error.InvalidRequest, http.parseRequestLine(line));
}

// Test parseHeader

test "parseHeader splits name and value" {
    const header = try http.parseHeader("Content-Type: text/plain");
    try std.testing.expectEqualStrings("Content-Type", header.name);
    try std.testing.expectEqualStrings("text/plain", header.value);
}

test "parseHeader trims extra whitespace around the value" {
    const header = try http.parseHeader("Content-Length:   42");
    try std.testing.expectEqualStrings("Content-Length", header.name);
    try std.testing.expectEqualStrings("42", header.value);
}

test "parseHeader rejects a line with no colon" {
    try std.testing.expectError(error.InvalidHeader, http.parseHeader("garbage"));
}

// Test readHeaderLine

test "readHeaderLine returns a single header line" {
    var reader: std.Io.Reader = .fixed("Host: example.com\r\n");
    const line = try http.readHeaderLine(&reader) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("Host: example.com", line);
}

test "readHeaderLine returns null on the blank line ending the headers" {
    var reader: std.Io.Reader = .fixed("\r\n");
    const line = try http.readHeaderLine(&reader);
    try std.testing.expectEqual(@as(?[]const u8, null), line);
}

test "readHeaderLine can be looped and composed with parseHeader" {
    var reader: std.Io.Reader = .fixed("Host: example.com\r\nContent-Length: 5\r\n\r\n");

    const first_line = try http.readHeaderLine(&reader) orelse return error.TestUnexpectedNull;
    const first = try http.parseHeader(first_line);
    try std.testing.expectEqualStrings("Host", first.name);
    try std.testing.expectEqualStrings("example.com", first.value);

    const second_line = try http.readHeaderLine(&reader) orelse return error.TestUnexpectedNull;
    const second = try http.parseHeader(second_line);
    try std.testing.expectEqualStrings("Content-Length", second.name);
    try std.testing.expectEqualStrings("5", second.value);

    const third_line = try http.readHeaderLine(&reader);
    try std.testing.expectEqual(@as(?[]const u8, null), third_line);
}
// Test readHeaders

// Test readHeaders

test "readHeaders returns an empty slice when there are no headers" {
    var reader: std.Io.Reader = .fixed("\r\n");

    const headers = try http.readHeaders(&reader, std.testing.allocator);
    defer http.freeHeaders(std.testing.allocator, headers);

    try std.testing.expectEqual(@as(usize, 0), headers.len);
}

test "readHeaders returns a standard amount of headers" {
    var reader: std.Io.Reader = .fixed(
        "Host: example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );

    const headers = try http.readHeaders(&reader, std.testing.allocator);
    defer http.freeHeaders(std.testing.allocator, headers);

    try std.testing.expectEqual(@as(usize, 3), headers.len);
    try std.testing.expectEqualStrings("Host", headers[0].name);
    try std.testing.expectEqualStrings("example.com", headers[0].value);
    try std.testing.expectEqualStrings("Content-Length", headers[1].name);
    try std.testing.expectEqualStrings("0", headers[1].value);
    try std.testing.expectEqualStrings("Connection", headers[2].name);
    try std.testing.expectEqualStrings("close", headers[2].value);
}

test "readHeaders frees partial progress when a header line is malformed" {
    var reader: std.Io.Reader = .fixed(
        "Host: example.com\r\ngarbage\r\nConnection: close\r\n\r\n",
    );

    // No `defer free` here — there's nothing to free. If readHeaders leaked
    // the "Host" entry it already collected before hitting the bad line,
    // std.testing.allocator would catch it and fail this test on its own.
    try std.testing.expectError(error.InvalidHeader, http.readHeaders(&reader, std.testing.allocator));
}

// Test readRequest

test "readRequest parses a request with no headers" {
    var reader: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n\r\n");
    const request = try http.readRequest(&reader, std.testing.allocator);
    defer request.deinit(std.testing.allocator);

    try std.testing.expectEqual(http.Method.GET, request.request_line.method);
    try std.testing.expectEqualStrings("/", request.request_line.path);
    try std.testing.expectEqual(http.Version.http_1_1, request.request_line.version);
    try std.testing.expectEqual(@as(usize, 0), request.headers.len);
}

test "readRequest parses a request with headers" {
    var reader: std.Io.Reader = .fixed(
        "POST /api/users HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    );
    const request = try http.readRequest(&reader, std.testing.allocator);
    defer request.deinit(std.testing.allocator);

    try std.testing.expectEqual(http.Method.POST, request.request_line.method);
    try std.testing.expectEqualStrings("/api/users", request.request_line.path);
    try std.testing.expectEqual(http.Version.http_1_1, request.request_line.version);

    try std.testing.expectEqual(@as(usize, 2), request.headers.len);
    try std.testing.expectEqualStrings("Host", request.headers[0].name);
    try std.testing.expectEqualStrings("example.com", request.headers[0].value);
    try std.testing.expectEqualStrings("Content-Length", request.headers[1].name);
    try std.testing.expectEqualStrings("0", request.headers[1].value);
}

// Testing Bodies

test "readRequest surfaces a bad request line" {
    var reader: std.Io.Reader = .fixed("PATCH /x HTTP/1.1\r\n\r\n");
    try std.testing.expectError(error.InvalidMethod, http.readRequest(&reader, std.testing.allocator));
}

test "readRequest frees the duped path when headers are malformed" {
    var reader: std.Io.Reader = .fixed("GET / HTTP/1.1\r\ngarbage\r\n\r\n");
    // No `defer deinit` — if readRequest leaked the duped `path` before
    // hitting the bad header line, std.testing.allocator catches it here.
    try std.testing.expectError(error.InvalidHeader, http.readRequest(&reader, std.testing.allocator));
}

test "readRequest with no Content-Length has a null body" {
    var reader: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n\r\n");
    const request = try http.readRequest(&reader, std.testing.allocator);
    defer request.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?[]u8, null), request.body);
}

test "readRequest reads a body matching Content-Length" {
    var reader: std.Io.Reader = .fixed(
        "POST /api/users HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
    );
    const request = try http.readRequest(&reader, std.testing.allocator);
    defer request.deinit(std.testing.allocator);

    const body = request.body orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("hello", body);
}

test "readRequest errors on a non-numeric Content-Length" {
    var reader: std.Io.Reader = .fixed(
        "POST / HTTP/1.1\r\nContent-Length: banana\r\n\r\nhello",
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        http.readRequest(&reader, std.testing.allocator),
    );
}

test "readRequest errors when the body is shorter than Content-Length claims" {
    var reader: std.Io.Reader = .fixed(
        "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nhello",
    );
    try std.testing.expectError(
        error.EndOfStream,
        http.readRequest(&reader, std.testing.allocator),
    );
}

test "readRequest is case-insensitive about the Content-Length header name" {
    var reader: std.Io.Reader = .fixed(
        "POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello",
    );
    const request = try http.readRequest(&reader, std.testing.allocator);
    defer request.deinit(std.testing.allocator);

    const body = request.body orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("hello", body);
}
