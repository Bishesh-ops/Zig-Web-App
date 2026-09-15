const std = @import("std");

pub const Method = enum {
    GET,
    POST,
    DELETE,
    PUT,
};
pub const Version = enum {
    http_1_0,
    http_1_1,
};

pub const RequestLine = struct {
    method: Method,
    path: []const u8,
    version: Version,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    request_line: RequestLine,
    headers: []Header,
    body: ?[]u8,
    ///Clean Deinit Function to Free all allocated memory for a `Request` in order.
    pub fn deinit(self: Request, allocator: std.mem.Allocator) void {
        allocator.free(self.request_line.path);
        freeHeaders(allocator, self.headers);
        if (self.body) |b| allocator.free(b);
    }
};

pub fn parseMethod(data: []const u8) !Method {
    const enum_value = std.meta.stringToEnum(Method, data);
    return enum_value orelse error.InvalidMethod;
}
pub fn parseVersion(data: []const u8) !Version {
    if (std.mem.eql(u8, data, "HTTP/1.0")) {
        return .http_1_0;
    } else if (std.mem.eql(u8, data, "HTTP/1.1")) {
        return .http_1_1;
    }
    return error.InvalidVersion;
}
///Parses the HTTP Requests without headers `data` is the actual RequestLine with headers.
pub fn parseRequestLine(data: []const u8) !RequestLine {
    const line = if (std.mem.find(u8, data, "\r\n")) |idx| data[0..idx] else data;

    var iter = std.mem.tokenizeAny(u8, line, " ");

    const method_str = iter.next() orelse return error.InvalidRequest;
    const path = iter.next() orelse return error.InvalidRequest;
    const version_str = iter.next() orelse return error.InvalidRequest;
    if (iter.next() != null) return error.InvalidRequest;

    return RequestLine{
        .method = try parseMethod(method_str),
        .path = path,
        .version = try parseVersion(version_str),
    };
}
///Reads and buffers bytes until it finds the delimiter, returning everything before it — the delimiter itself is left in the stream, so it is swallowed seperately.
pub fn readRequestLine(reader: *std.Io.Reader) ![]const u8 {
    const raw_line = try reader.takeDelimiterExclusive('\n');
    const line = std.mem.trimEnd(u8, raw_line, "\r");
    _ = reader.takeByte() catch {};
    return line;
}

pub fn parseHeader(data: []const u8) !Header {
    const colon_idx = std.mem.indexOfScalar(u8, data, ':') orelse return error.InvalidHeader;
    const name = data[0..colon_idx];
    if (name.len == 0) return error.InvalidHeader;

    const value = std.mem.trim(u8, data[colon_idx + 1 ..], " \t");

    return Header{ .name = name, .value = value };
}

pub fn readHeaderLine(reader: *std.Io.Reader) !?[]const u8 {
    const raw_line = try reader.takeDelimiterExclusive('\n');
    const line = std.mem.trimEnd(u8, raw_line, "\r");
    _ = reader.takeByte() catch {};

    if (line.len == 0) return null;
    return line;
}

pub fn readHeaders(reader: *std.Io.Reader, allocator: std.mem.Allocator) ![]Header {
    var list: std.ArrayList(Header) = .empty;
    errdefer {
        for (list.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        list.deinit(allocator);
    }

    while (try readHeaderLine(reader)) |line| {
        const parsed = try parseHeader(line);
        const name = try allocator.dupe(u8, parsed.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, parsed.value);
        try list.append(allocator, .{ .name = name, .value = value });
    }

    return list.toOwnedSlice(allocator);
}

pub fn readRequest(reader: *std.Io.Reader, allocator: std.mem.Allocator) !Request {
    const raw_line = try readRequestLine(reader);
    const parsed_line = try parseRequestLine(raw_line);

    const path = try allocator.dupe(u8, parsed_line.path);
    errdefer allocator.free(path);

    const headers = try readHeaders(reader, allocator);
    errdefer freeHeaders(allocator, headers);

    const body = try readBody(reader, allocator, headers);

    return Request{
        .request_line = .{
            .method = parsed_line.method,
            .path = path,
            .version = parsed_line.version,
        },
        .headers = headers,
        .body = body,
    };
}

pub fn freeHeaders(allocator: std.mem.Allocator, headers: []Header) void {
    for (headers) |h| {
        allocator.free(h.name);
        allocator.free(h.value);
    }
    allocator.free(headers);
}
fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

pub fn readBody(reader: *std.Io.Reader, allocator: std.mem.Allocator, headers: []const Header) !?[]u8 {
    const content_length_str = findHeader(headers, "Content-Length") orelse return null;
    const content_length = std.fmt.parseInt(usize, content_length_str, 10) catch return error.InvalidContentLength;
    if (content_length == 0) return null;

    const body = try allocator.alloc(u8, content_length);
    errdefer allocator.free(body);

    try reader.readSliceAll(body);
    return body;
}
