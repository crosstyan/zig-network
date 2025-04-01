const std = @import("std");
const os = @import("os");
const builtin = @import("builtin");
const posix = std.posix;

comptime {
    std.debug.assert(@sizeOf(std.posix.sockaddr) >= @sizeOf(std.posix.sockaddr.in));
}

const is_windows = builtin.os.tag == .windows;
const is_darwin = builtin.os.tag.isDarwin();
const is_linux = builtin.os.tag == .linux;
const is_freebsd = builtin.os.tag == .freebsd;
const is_openbsd = builtin.os.tag == .openbsd;
const is_netbsd = builtin.os.tag == .netbsd;
const is_dragonfly = builtin.os.tag == .dragonfly;

// use these to test collections of OS type
const is_bsd = builtin.os.tag.isBSD();
const is_unix = is_bsd or is_linux;

pub fn init() error{InitializationError}!void {
    if (is_windows) {
        _ = windows.WSAStartup(2, 2) catch return error.InitializationError;
    }
}

pub fn deinit() void {
    if (is_windows) {
        windows.WSACleanup() catch return;
    }
}

const IPv4ParseError = std.net.IPv4ParseError;

/// A network address abstraction. Contains one member for each possible type of address.
pub const Address = union(AddressFamily) {
    ipv4: IPv4,
    ipv6: IPv6,

    pub fn parse(string: []const u8) !Address {
        return if (Address.IPv4.parse(string)) |ip|
            Address{ .ipv4 = ip }
        else |_| if (Address.IPv6.parse(string)) |ip|
            Address{ .ipv6 = ip }
        else |_|
            return error.InvalidFormat;
    }

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Address {
        _ = allocator;

        var buffer: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);

        const str = try std.json.innerParse([]const u8, fba.allocator(), source, options);

        return parse(str) catch return error.UnexpectedToken;
    }

    pub const IPv4 = struct {
        const Self = @This();

        pub const any = IPv4.init(0, 0, 0, 0);
        pub const broadcast = IPv4.init(255, 255, 255, 255);
        pub const loopback = IPv4.init(127, 0, 0, 1);
        pub const multicast_all = IPv4.init(224, 0, 0, 1);

        value: [4]u8,

        pub fn init(a: u8, b: u8, c: u8, d: u8) Self {
            return Self{
                .value = [4]u8{ a, b, c, d },
            };
        }

        pub fn eql(lhs: Self, rhs: Self) bool {
            return std.mem.eql(u8, &lhs.value, &rhs.value);
        }

        pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            // https://zig.guide/standard-library/readers-and-writers
            const sz: comptime_int = 3 * 4 + 3;
            var buf: [sz]u8 = undefined;
            const s = try std.fmt.bufPrint(buf[0..], "{}.{}.{}.{}", .{
                value.value[0],
                value.value[1],
                value.value[2],
                value.value[3],
            });
            try writer.writeAll(s);
        }

        pub fn parse(buf: []const u8) IPv4ParseError!IPv4 {
            // steal from std.net implementation
            var result: IPv4 = undefined;
            const out_ptr = std.mem.asBytes(&result.value);

            var x: u8 = 0;
            var index: u8 = 0;
            var saw_any_digits = false;
            var has_zero_prefix = false;
            for (buf) |c| {
                if (c == '.') {
                    if (!saw_any_digits) {
                        return error.InvalidCharacter;
                    }
                    if (index == 3) {
                        return error.InvalidEnd;
                    }
                    out_ptr[index] = x;
                    index += 1;
                    x = 0;
                    saw_any_digits = false;
                    has_zero_prefix = false;
                } else if (c >= '0' and c <= '9') {
                    if (c == '0' and !saw_any_digits) {
                        has_zero_prefix = true;
                    } else if (has_zero_prefix) {
                        return error.NonCanonical;
                    }
                    saw_any_digits = true;
                    x = try std.math.mul(u8, x, 10);
                    x = try std.math.add(u8, x, c - '0');
                } else {
                    return error.InvalidCharacter;
                }
            }
            if (index == 3 and saw_any_digits) {
                out_ptr[index] = x;
                return result;
            }

            return error.Incomplete;
        }

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !IPv4 {
            _ = allocator;

            var buffer: [256]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buffer);

            const str = try std.json.innerParse([]const u8, fba.allocator(), source, options);

            return IPv4.parse(str) catch return error.UnexpectedToken;
        }
    };

    pub const IPv6 = struct {
        const Self = @This();

        pub const any = std.mem.zeroes(Self);
        pub const loopback = IPv6.init([1]u8{0} ** 15 ++ [1]u8{1}, 0);

        value: [16]u8,
        scope_id: u32,

        pub fn init(value: [16]u8, scope_id: u32) Self {
            return Self{ .value = value, .scope_id = scope_id };
        }

        pub fn eql(lhs: Self, rhs: Self) bool {
            return std.mem.eql(u8, &lhs.value, &rhs.value) and
                lhs.scope_id == rhs.scope_id;
        }

        pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            if (std.mem.eql(u8, self.value[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                try std.fmt.format(writer, "[::ffff:{}.{}.{}.{}]", .{
                    self.value[12],
                    self.value[13],
                    self.value[14],
                    self.value[15],
                });
                return;
            }
            const big_endian_parts: *align(1) const [8]u16 = @ptrCast(&self.value);
            const native_endian_parts = switch (builtin.target.cpu.arch.endian()) {
                .big => big_endian_parts.*,
                .little => blk: {
                    var buf: [8]u16 = undefined;
                    for (big_endian_parts, 0..) |part, i| {
                        buf[i] = std.mem.bigToNative(u16, part);
                    }
                    break :blk buf;
                },
            };
            try writer.writeAll("[");
            var i: usize = 0;
            var abbrv = false;
            while (i < native_endian_parts.len) : (i += 1) {
                if (native_endian_parts[i] == 0) {
                    if (!abbrv) {
                        try writer.writeAll(if (i == 0) "::" else ":");
                        abbrv = true;
                    }
                    continue;
                }
                try std.fmt.format(writer, "{x}", .{native_endian_parts[i]});
                if (i != native_endian_parts.len - 1) {
                    try writer.writeAll(":");
                }
            }
            try writer.writeAll("]");
        }

        /// Parse an IPv6 representation according to the canonical format
        /// described in
        /// [RFC5952](https://datatracker.ietf.org/doc/html/rfc5952). The
        /// "scope ID" (otherwise known as "zone ID", `<zone_id>`) is
        /// intentionally not supported as parsing according to
        /// [RFC6874](https://datatracker.ietf.org/doc/html/rfc6874) is highly
        /// platform-specific and difficult to validate.
        /// (See https://www.w3.org/Bugs/Public/show_bug.cgi?id=27234#c2).
        pub fn parse(string: []const u8) !IPv6 {
            if (string.len < 2 or string.len > 39) {
                return error.InvalidFormat;
            }
            // Address cannot start or end with a single ':'.
            if ((string[0] == ':' and string[1] != ':') or
                (string[string.len - 2] != ':' and
                    string[string.len - 1] == ':'))
            {
                return error.InvalidFormat;
            }

            var ip: IPv6 = .{ .value = undefined, .scope_id = 0 };
            // Group index of abbreviation, to know how many groups have been
            // abbreviated.
            var abbreviated: ?u3 = null;
            // Current group index.
            var cg_index: u3 = 0;
            var groups: [8][]const u8 = .{""} ** 8;

            groups[0].ptr = string.ptr;

            for (string, 0..) |c, i| {
                switch (c) {
                    ':' => {
                        // Check for "::".
                        if (i + 1 < string.len and string[i + 1] == ':') {
                            // "::" cannot appear more than once.
                            if (abbreviated) |_| {
                                return error.InvalidFormat;
                            }
                            abbreviated = cg_index;
                            continue;
                        }

                        var abbreviation_ending: bool = false;
                        if (abbreviated != null and abbreviated.? == cg_index) {
                            // This ':' is the second in "::".
                            abbreviation_ending = true;
                        }

                        // Empty groups are not allowed, unless
                        // leading/trailing abbreviation.
                        if (groups[cg_index].len == 0 and
                            (!abbreviation_ending or
                                (i != 1 and i != string.len - 1)))
                        {
                            return error.InvalidFormat;
                        }

                        // Exactly 8 groups are allowed in a valid address.
                        if (cg_index == 7) {
                            return error.InvalidFormat;
                        }

                        cg_index += 1;
                        groups[cg_index].ptr = string[i + 1 ..].ptr;
                    },
                    'a'...'f', 'A'...'F', '0'...'9' => {
                        groups[cg_index].len += 1;
                    },
                    else => {
                        return error.InvalidFormat;
                    },
                }
            }

            // Reorder groups to expand to exactly 8 groups if abbreviated.
            if (cg_index != 7) {
                if (abbreviated) |index| {
                    // Number of groups that must be copied past abbreviation
                    // expansion.
                    const num_groups_copy: usize = cg_index - index;
                    std.mem.copyBackwards(
                        []const u8,
                        groups[8 - num_groups_copy ..],
                        groups[index + 1 .. cg_index + 1],
                    );
                    @memset(groups[index + 1 .. 8 - num_groups_copy], "");
                } else {
                    return error.InvalidFormat;
                }
            }

            // Parse groups, after accounting for abbreviations.
            for (groups, 0..) |group, i| {
                if (group.len > 4) {
                    return error.InvalidFormat;
                }

                // Second byte in group to be parsed.
                var b2 = group;

                // First byte exists.
                if (group.len > 2) {
                    ip.value[i * 2] = try std.fmt.parseInt(
                        u8,
                        group[0 .. group.len - 2],
                        16,
                    );
                    b2 = group[group.len - 2 ..];
                } else {
                    ip.value[i * 2] = 0;
                }

                if (group.len > 0) {
                    ip.value[i * 2 + 1] = try std.fmt.parseInt(u8, b2, 16);
                } else {
                    ip.value[i * 2 + 1] = 0;
                }
            }

            return ip;
        }
    };

    pub fn format(value: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        switch (value) {
            .ipv4 => |a| try a.format(fmt, options, writer),
            .ipv6 => |a| try a.format(fmt, options, writer),
        }
    }

    pub fn eql(lhs: @This(), rhs: @This()) bool {
        if (@as(AddressFamily, lhs) != @as(AddressFamily, rhs))
            return false;
        return switch (lhs) {
            .ipv4 => |l| l.eql(rhs.ipv4),
            .ipv6 => |l| l.eql(rhs.ipv6),
        };
    }
};

pub const AddressFamily = enum {
    const Self = @This();

    ipv4,
    ipv6,

    pub fn toNativeAddressFamily(af: Self) u32 {
        return switch (af) {
            .ipv4 => std.posix.AF.INET,
            .ipv6 => std.posix.AF.INET6,
        };
    }

    pub fn fromNativeAddressFamily(af: i32) AddressFamilyError!Self {
        return switch (af) {
            std.posix.AF.INET => .ipv4,
            std.posix.AF.INET6 => .ipv6,
            else => return error.UnsupportedAddressFamily,
        };
    }
};

/// Protocols supported by this library.
pub const Protocol = enum {
    const Self = @This();

    tcp,
    udp,

    fn toSocketType(proto: Self) u32 {
        return switch (proto) {
            .tcp => std.posix.SOCK.STREAM,
            .udp => std.posix.SOCK.DGRAM,
        };
    }
};

/// A network end point. Is composed of an address and a port.
pub const EndPoint = struct {
    const Self = @This();

    address: Address,
    port: u16, // Stored as native, will convert to bigEndian when moving to sockaddr

    pub fn parse(string: []const u8) !EndPoint {
        const colon_index = std.mem.lastIndexOfScalar(u8, string, ':') orelse return error.InvalidFormat;

        const address = try Address.parse(string[0..colon_index]);

        const port = try std.fmt.parseInt(u16, string[colon_index + 1 ..], 10);

        return EndPoint{
            .address = address,
            .port = port,
        };
    }

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !EndPoint {
        _ = allocator;

        var buffer: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);

        const str = try std.json.innerParse([]const u8, fba.allocator(), source, options);

        return parse(str) catch return error.UnexpectedToken;
    }

    pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        const sz: comptime_int = 39 + 5 + 1;
        var buf: [sz]u8 = undefined;
        const s = try std.fmt.bufPrint(buf[0..], "{}:{}", .{
            value.address,
            value.port,
        });
        try writer.writeAll(s);
    }

    pub fn fromSocketAddress(src: *const std.posix.sockaddr, size: usize) !Self {
        switch (src.family) {
            std.posix.AF.INET => {
                if (size < @sizeOf(std.posix.sockaddr.in))
                    return error.InsufficientBytes;
                const value: *align(4) const std.posix.sockaddr.in = @ptrCast(@alignCast(src));
                return EndPoint{
                    .port = std.mem.bigToNative(u16, value.port),
                    .address = .{
                        .ipv4 = .{
                            .value = @bitCast(value.addr),
                        },
                    },
                };
            },
            std.posix.AF.INET6 => {
                if (size < @sizeOf(std.posix.sockaddr.in6))
                    return error.InsufficientBytes;
                const value: *align(4) const std.posix.sockaddr.in6 = @ptrCast(@alignCast(src));
                return EndPoint{
                    .port = std.mem.bigToNative(u16, value.port),
                    .address = .{
                        .ipv6 = .{
                            .value = value.addr,
                            .scope_id = value.scope_id,
                        },
                    },
                };
            },
            else => {
                std.log.info("got invalid socket address: {}\n", .{src});
                return error.UnsupportedAddressFamily;
            },
        }
    }

    pub const SockAddr = union(AddressFamily) {
        ipv4: std.posix.sockaddr.in,
        ipv6: std.posix.sockaddr.in6,
    };

    fn toSocketAddress(self: Self) SockAddr {
        return switch (self.address) {
            .ipv4 => |addr| SockAddr{
                .ipv4 = .{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, self.port),
                    .addr = @bitCast(addr.value),
                    .zero = [_]u8{0} ** 8,
                },
            },
            .ipv6 => |addr| SockAddr{
                .ipv6 = .{
                    .family = std.posix.AF.INET6,
                    .port = std.mem.nativeToBig(u16, self.port),
                    .flowinfo = 0,
                    .addr = addr.value,
                    .scope_id = addr.scope_id,
                },
            },
        };
    }
};

pub const AcceptError = std.posix.AcceptError || AddressFamilyError;
/// A network socket, can receive and send data for TCP/UDP and accept
/// incoming connections if bound as a TCP server.
pub const Socket = struct {
    pub const SendError = (std.posix.SendError || std.posix.SendToError);
    pub const ReceiveError = std.posix.RecvFromError;

    pub const Reader = std.io.Reader(Socket, ReceiveError, receive);
    pub const Writer = std.io.Writer(Socket, SendError, send);

    const Self = @This();

    family: AddressFamily,
    internal: std.posix.socket_t,
    endpoint: ?EndPoint,

    /// Spawns a new socket that must be freed with `close()`.
    /// `family` defines the socket family, `protocol` the protocol used.
    pub fn create(family: AddressFamily, protocol: Protocol) !Self {
        const socket_fn = if (is_windows) windows.socket else std.posix.socket;

        // std provides a shim for Darwin to set SOCK_NONBLOCK.
        // Socket creation will only set the flag if we provide the shim rather than the actual flag.
        const socket_type = if (is_unix)
            protocol.toSocketType() | std.posix.SOCK.CLOEXEC
        else
            protocol.toSocketType();

        return Self{
            .family = family,
            .internal = try socket_fn(family.toNativeAddressFamily(), socket_type, 0),
            .endpoint = null,
        };
    }

    /// Closes the socket and releases its resources.
    pub fn close(self: Self) void {
        std.posix.close(self.internal);
    }

    /// Binds the socket to the given end point.
    pub fn bind(self: *Self, ep: EndPoint) !void {
        switch (ep.toSocketAddress()) {
            .ipv4 => |sockaddr| try std.posix.bind(
                self.internal,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ),
            .ipv6 => |sockaddr| try std.posix.bind(
                self.internal,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ),
        }
    }

    /// Binds the socket to all supported addresses on the local device.
    /// This will use the any IP (`0.0.0.0` for IPv4).
    pub fn bindToPort(self: *Self, port: u16) !void {
        return switch (self.family) {
            .ipv4 => self.bind(EndPoint{
                .address = Address{ .ipv4 = Address.IPv4.any },
                .port = port,
            }),
            .ipv6 => self.bind(EndPoint{
                .address = Address{ .ipv6 = Address.IPv6.any },
                .port = port,
            }),
        };
    }

    /// Set socket timeouts for read and write in microseconds
    pub fn setTimeouts(self: *Self, read: ?u32, write: ?u32) !void {
        try self.setReadTimeout(read);
        try self.setWriteTimeout(write);
    }

    /// Set socket read timeout in microseconds
    pub fn setReadTimeout(self: *Self, read: ?u32) !void {
        std.debug.assert(read == null or read.? != 0);
        const micros = read orelse 0;
        var opt = if (is_windows) @as(u32, @divTrunc(micros, 1000)) else std.posix.timeval{
            .sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
            .usec = @intCast(@mod(micros, std.time.us_per_s)),
        };
        try std.posix.setsockopt(
            self.internal,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            if (is_windows) std.mem.asBytes(&opt) else std.mem.toBytes(opt)[0..],
        );
    }

    /// Set socket write timeout in microseconds
    pub fn setWriteTimeout(self: *Self, write: ?u32) !void {
        std.debug.assert(write == null or write.? != 0);
        const micros = write orelse 0;
        var opt = if (is_windows) @as(u32, @divTrunc(micros, 1000)) else std.posix.timeval{
            .sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
            .usec = @intCast(@mod(micros, std.time.us_per_s)),
        };
        try std.posix.setsockopt(
            self.internal,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDTIMEO,
            if (is_windows) std.mem.asBytes(&opt) else std.mem.toBytes(opt)[0..],
        );
    }

    /// Sets the SO_BROADCAST socket option to enable/disable UDP broadcast. Only supported for IPv4.
    pub fn setBroadcast(self: *Self, enable: bool) !void {
        std.debug.assert(self.family == .ipv4);

        const val: u32 = if (enable) 1 else 0;
        try std.posix.setsockopt(self.internal, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, std.mem.asBytes(&val));
    }

    /// Connects the UDP or TCP socket to a remote server.
    /// The `target` address type must fit the address type of the socket.
    pub fn connect(self: *Self, target: EndPoint) !void {
        if (target.address != self.family)
            return error.AddressFamilyMismach;

        // on darwin you set the NOSIGNAl once, rather than for each message
        if (is_bsd) {
            // set the options to ON
            const value: u32 = 1;
            try std.posix.setsockopt(
                self.internal,
                std.posix.SOL.SOCKET,
                std.c.SO.NOSIGPIPE,
                std.mem.asBytes(&value),
            );
        }

        switch (target.toSocketAddress()) {
            .ipv4 => |sockaddr| std.posix.connect(
                self.internal,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ) catch |e| {
                // NOTE: Windows sockets return `ConnectionTimedOut` when equivalent POSIX sockets
                // return `WouldBlock`. Wrapping Windows socket `ConnectionTimedOut` errors here is
                // necessary to match behavior for `std.posix.connect` and `std.posix.recvfrom`.
                if (is_windows and e == std.posix.ConnectError.ConnectionTimedOut) {
                    return std.posix.ConnectError.WouldBlock;
                }
                return e;
            },
            .ipv6 => |sockaddr| std.posix.connect(
                self.internal,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ) catch |e| {
                // NOTE: Windows sockets return `ConnectionTimedOut` when equivalent POSIX sockets
                // return `WouldBlock`. Wrapping Windows socket `ConnectionTimedOut` errors here is
                // necessary to match behavior for `std.posix.connect` and `std.posix.recvfrom`.
                if (is_windows and e == std.posix.ConnectError.ConnectionTimedOut) {
                    return std.posix.ConnectError.WouldBlock;
                }
                return e;
            },
        }
        self.endpoint = target;
    }

    /// Makes this socket a TCP server and allows others to connect to
    /// this socket.
    /// Call `accept()` to handle incoming connections.
    pub fn listen(self: Self) !void {
        try std.posix.listen(self.internal, 0);
    }

    /// Waits until a new TCP client connects to this socket and accepts the incoming TCP connection.
    /// This function is only allowed for a bound TCP socket. `listen()` must have been called before!
    pub fn accept(self: Self) AcceptError!Socket {
        var addr: std.posix.sockaddr.in6 = undefined;
        var addr_size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

        // Add SOCK_NONBLOCK flag for Unix systems to make accepted sockets non-blocking
        const flags = if (is_unix) std.posix.SOCK.NONBLOCK else 0;

        const addr_ptr: *std.posix.sockaddr = @ptrCast(&addr);
        const fd = try std.posix.accept(self.internal, addr_ptr, &addr_size, flags);
        errdefer std.posix.close(fd);

        return Socket{
            .family = try AddressFamily.fromNativeAddressFamily(addr_ptr.family),
            .internal = fd,
            .endpoint = null,
        };
    }

    /// Send some data to the connected peer. In UDP, this
    /// will always send full packets, on TCP it will append
    /// to the stream.
    pub fn send(self: Self, data: []const u8) SendError!usize {
        if (self.endpoint) |ep|
            return try self.sendTo(ep, data);
        const flags = if (is_windows or is_bsd) 0 else std.os.linux.MSG.NOSIGNAL;
        return try std.posix.send(self.internal, data, flags);
    }

    /// Non-Blockingly peeks at data from the connected peer.
    /// Will not change the stream state.
    pub fn peek(self: Self, data: []u8) ReceiveError!usize {
        const recvfrom_fn = if (is_windows) windows.recvfrom else std.posix.recvfrom;
        const flags = if (is_windows) 0x2 else std.os.linux.MSG.PEEK;
        return try recvfrom_fn(self.internal, data, flags, null, null);
    }

    /// Blockingly receives some data from the connected peer.
    /// Will read all available data from the TCP stream or
    /// a UDP packet.
    pub fn receive(self: Self, data: []u8) ReceiveError!usize {
        const recvfrom_fn = if (is_windows) windows.recvfrom else std.posix.recvfrom;
        const flags = if (is_windows or is_bsd) 0 else std.os.linux.MSG.NOSIGNAL;
        return try recvfrom_fn(self.internal, data, flags, null, null);
    }

    const ReceiveFrom = struct { numberOfBytes: usize, sender: EndPoint };

    /// Same as ´receive`, but will also return the end point from which the data
    /// was received. This is only a valid operation on UDP sockets.
    pub fn receiveFrom(self: Self, data: []u8) !ReceiveFrom {
        const recvfrom_fn = if (is_windows) windows.recvfrom else std.posix.recvfrom;
        const flags = if (is_linux) std.os.linux.MSG.NOSIGNAL else 0;

        // Use the ipv6 sockaddr to guarantee data will fit.
        var addr: std.posix.sockaddr.in6 align(4) = undefined;
        var size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

        const addr_ptr: *std.posix.sockaddr = @ptrCast(&addr);
        const len = try recvfrom_fn(self.internal, data, flags | if (is_windows) 0 else 4, addr_ptr, &size);

        return ReceiveFrom{
            .numberOfBytes = len,
            .sender = try EndPoint.fromSocketAddress(addr_ptr, size),
        };
    }

    /// Sends a packet to a given network end point. Behaves the same as `send()`, but will only work for
    /// for UDP sockets.
    pub fn sendTo(self: Self, receiver: EndPoint, data: []const u8) SendError!usize {
        const flags = if (is_windows or is_bsd) 0 else std.os.linux.MSG.NOSIGNAL;

        const saddr = receiver.toSocketAddress();

        const len = switch (saddr) {
            .ipv4 => |sockaddr| try sendto(
                self.internal,
                data,
                flags,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ),
            .ipv6 => |sockaddr| try sendto(
                self.internal,
                data,
                flags,
                @ptrCast(&sockaddr),
                @sizeOf(@TypeOf(sockaddr)),
            ),
        };

        return len;
    }
    // .darwin returns ISCONN error for already connected socket
    // .windows and .lynux both don't care
    // Intercepts ISCONN status for .darwin and retry sendto with null destination address
    pub fn sendto(
        /// The file descriptor of the sending socket.
        sockfd: std.posix.socket_t,
        /// Message to send.
        buf: []const u8,
        flags: u32,
        dest_addr: ?*const std.posix.sockaddr,
        addrlen: std.posix.socklen_t,
    ) std.posix.SendToError!usize {
        if (!is_darwin) {
            return std.posix.sendto(sockfd, buf, flags, dest_addr, addrlen);
        }
        while (true) {
            const rc = std.posix.system.sendto(sockfd, buf.ptr, buf.len, flags, dest_addr, addrlen);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),

                .ACCES => return error.AccessDenied,
                .AGAIN => return error.WouldBlock,
                .ALREADY => return error.FastOpenAlreadyInProgress,
                .BADF => unreachable, // always a race condition
                .CONNRESET => return error.ConnectionResetByPeer,
                .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
                .FAULT => unreachable, // An invalid user space address was specified for an argument.
                .INTR => continue,
                .INVAL => return error.UnreachableAddress,
                // connection-mode socket was connected already but a recipient was specified
                // sendto using NULL destination address
                .ISCONN => return std.posix.sendto(sockfd, buf, flags, null, 0),
                .MSGSIZE => return error.MessageTooLong,
                .NOBUFS => return error.SystemResources,
                .NOMEM => return error.SystemResources,
                .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
                .PIPE => return error.BrokenPipe,
                .AFNOSUPPORT => return error.AddressFamilyNotSupported,
                .LOOP => return error.SymLinkLoop,
                .NAMETOOLONG => return error.NameTooLong,
                .NOENT => return error.FileNotFound,
                .NOTDIR => return error.NotDir,
                .HOSTUNREACH => return error.NetworkUnreachable,
                .NETUNREACH => return error.NetworkUnreachable,
                .NOTCONN => return error.SocketNotConnected,
                .NETDOWN => return error.NetworkSubsystemFailed,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    }

    /// Sets the socket option `SO_REUSEPORT` which allows
    /// multiple bindings of the same socket to the same address
    /// on UDP sockets and allows quicker re-binding of TCP sockets.
    pub fn enablePortReuse(self: Self, enabled: bool) !void {
        var opt: c_int = if (enabled) 1 else 0;
        try std.posix.setsockopt(
            self.internal,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEADDR,
            std.mem.asBytes(&opt),
        );
    }

    /// Retrieves the end point to which the socket is bound.
    pub fn getLocalEndPoint(self: Self) !EndPoint {
        var addr: std.posix.sockaddr.in6 align(4) = undefined;
        var size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

        const addr_ptr: *std.posix.sockaddr = @ptrCast(&addr);
        try std.posix.getsockname(self.internal, addr_ptr, &size);

        return try EndPoint.fromSocketAddress(addr_ptr, size);
    }

    /// Retrieves the end point to which the socket is connected.
    pub fn getRemoteEndPoint(self: Self) !EndPoint {
        var addr: std.posix.sockaddr.in6 align(4) = undefined;
        var size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

        const addr_ptr: *std.posix.sockaddr = @ptrCast(&addr);
        try std.posix.getpeername(self.internal, addr_ptr, &size);

        return try EndPoint.fromSocketAddress(addr_ptr, size);
    }

    pub const MulticastGroup = struct {
        interface: Address.IPv4,
        group: Address.IPv4,
    };

    /// Joins the UDP socket into a multicast group.
    /// Multicast enables sending packets to the group and all joined peers
    /// will receive the sent data.
    pub fn joinMulticastGroup(self: Self, group: MulticastGroup) !void {
        // Windows uses a different structure for IP_ADD_MEMBERSHIP
        if (is_windows) {
            return windows.joinMulticastGroup(self.internal, group);
        }

        const ip_mreqn = extern struct {
            imr_multiaddr: c_int,
            imr_address: c_int,
            // FreeBSD: https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4
            //  if imr_ifindex is 0, kernel will use IP address from
            //  imr_interface to lookup the interface.
            // Linux: https://man7.org/linux/man-pages/man7/ip.7.html
            //  imr_ifindex is the interface index of the interface that should
            //  join/leave the imr_multiaddr group, or 0 to indicate any
            //  interface.
            imr_ifindex: c_int,
        };

        const request = ip_mreqn{
            .imr_multiaddr = @bitCast(group.group.value),
            .imr_address = @bitCast(group.interface.value),
            .imr_ifindex = 0, // this cannot be crossplatform, so we set it to zero
        };

        const IP_ADD_MEMBERSHIP_BSD = 12;
        const IP_ADD_MEMBERSHIP_LINUX = std.os.linux.IP.ADD_MEMBERSHIP;
        const IP_ADD_MEMBERSHIP = if (is_bsd) IP_ADD_MEMBERSHIP_BSD else IP_ADD_MEMBERSHIP_LINUX;
        const level = std.posix.IPPROTO.IP;

        try std.posix.setsockopt(
            self.internal,
            level,
            IP_ADD_MEMBERSHIP,
            std.mem.asBytes(&request),
        );
    }

    /// Gets an reader that allows reading data from the socket.
    pub fn reader(self: Self) Reader {
        return .{ .context = self };
    }

    /// Gets a writer that allows writing data to the socket.
    pub fn writer(self: Self) Writer {
        return .{ .context = self };
    }
};

/// A socket event that can be waited for.
pub const SocketEvent = struct {
    /// Wait for data ready to be read.
    read: bool,

    /// Wait for all pending data to be sent and the socket accepting
    /// non-blocking writes.
    write: bool,
};

/// A set of sockets that can be used to query socket readiness.
/// This is similar to `select()´ or `poll()` and provides a way to
/// create non-blocking socket I/O.
/// This is intended to be used with `waitForSocketEvents()`.
pub const SocketSet = struct {
    const Self = @This();

    internal: OSLogic,

    /// Initialize a new socket set. This can be reused for
    /// multiple queries without having to reset the set every time.
    /// Call `deinit()` to free the socket set.
    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .internal = try OSLogic.init(allocator),
        };
    }

    /// Frees the contained resources.
    pub fn deinit(self: *Self) void {
        self.internal.deinit();
    }

    /// Removes all sockets from the set.
    pub fn clear(self: *Self) void {
        self.internal.clear();
    }

    /// Adds a socket to the set and enables waiting for any of the events
    /// in `events`.
    pub fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
        try self.internal.add(sock, events);
    }

    /// Removes the socket from the set.
    pub fn remove(self: *Self, sock: Socket) void {
        self.internal.remove(sock);
    }

    /// Checks if the socket is ready to be read.
    /// Only valid after the first call to `waitForSocketEvent()`.
    pub fn isReadyRead(self: Self, sock: Socket) bool {
        return self.internal.isReadyRead(sock);
    }

    /// Checks if the socket is ready to be written.
    /// Only valid after the first call to `waitForSocketEvent()`.
    pub fn isReadyWrite(self: Self, sock: Socket) bool {
        return self.internal.isReadyWrite(sock);
    }

    /// Checks if the socket is faulty and cannot be used anymore.
    /// Only valid after the first call to `waitForSocketEvent()`.
    pub fn isFaulted(self: Self, sock: Socket) bool {
        return self.internal.isFaulted(sock);
    }
};

/// Implementation of SocketSet for each platform,
/// keeps the thing above nice and clean, all functions get inlined.
const OSLogic = switch (builtin.os.tag) {
    .windows => WindowsOSLogic,
    .linux => LinuxOSLogic,
    .macos, .ios, .watchos, .tvos => DarwinOsLogic,
    else => if (is_bsd) UnixOSLogic else @compileError("unsupported os " ++ @tagName(builtin.os.tag) ++ " for SocketSet!"),
};

// Linux uses `epoll()` syscall to wait for socket events.
// which is more efficient than `poll()`
const LinuxOSLogic = struct {
    const Self = @This();

    epoll_fd: i32,
    events: std.ArrayList(std.os.linux.epoll_event),
    socket_map: std.AutoHashMap(i32, SocketEvent),
    allocator: std.mem.Allocator,

    inline fn init(allocator: std.mem.Allocator) !Self {
        const fd = std.os.linux.epoll_create1(0);

        // negative value
        if (fd > std.math.maxInt(i32)) {
            const errno = std.os.linux.E.init(fd);
            // TODO: convert to error set
            return std.posix.unexpectedErrno(errno);
        }

        const epoll_fd: i32 = @intCast(fd);
        errdefer std.posix.close(epoll_fd);

        return Self{
            .epoll_fd = epoll_fd,
            .events = try std.ArrayList(std.os.linux.epoll_event).initCapacity(allocator, 16),
            .socket_map = std.AutoHashMap(i32, SocketEvent).init(allocator),
            .allocator = allocator,
        };
    }

    inline fn deinit(self: *Self) void {
        self.events.deinit();
        self.socket_map.deinit();
        std.posix.close(self.epoll_fd);
    }

    inline fn clear(self: *Self) void {
        var it = self.socket_map.iterator();
        while (it.next()) |entry| {
            _ = std.os.linux.epoll_ctl(
                self.epoll_fd,
                std.os.linux.EPOLL.CTL_DEL,
                entry.key_ptr.*,
                null,
            ) catch {};
        }
        self.socket_map.clearRetainingCapacity();
        self.events.clearRetainingCapacity();
    }

    inline fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
        var op: u32 = undefined;
        if (self.socket_map.contains(sock.internal)) {
            op = std.os.linux.EPOLL.CTL_MOD;
        } else {
            op = std.os.linux.EPOLL.CTL_ADD;
        }

        var event_mask: u32 = std.os.linux.EPOLL.ERR;
        if (events.read)
            event_mask |= std.os.linux.EPOLL.IN;
        if (events.write)
            event_mask |= std.os.linux.EPOLL.OUT;

        var ev = std.os.linux.epoll_event{
            .events = event_mask,
            .data = .{ .fd = sock.internal },
        };

        var rc: usize = undefined;
        rc = std.os.linux.epoll_ctl(
            self.epoll_fd,
            op,
            sock.internal,
            &ev,
        );

        // negative value
        // https://man7.org/linux/man-pages/man2/epoll_ctl.2.html
        if (rc > std.math.maxInt(i32)) {
            const errno = std.os.linux.E.init(rc);
            // TODO: convert to error set
            return std.posix.unexpectedErrno(errno);
        }

        try self.socket_map.put(sock.internal, events);
    }

    inline fn remove(self: *Self, sock: Socket) void {
        if (self.socket_map.contains(sock.internal)) {
            // TODO: error handling
            _ = std.os.linux.epoll_ctl(
                self.epoll_fd,
                std.os.linux.EPOLL.CTL_DEL,
                sock.internal,
                null,
            );
            _ = self.socket_map.remove(sock.internal);
        }
    }

    inline fn isReadyRead(self: Self, sock: Socket) bool {
        for (self.events.items) |ev| {
            if (ev.data.fd == sock.internal) {
                return (ev.events & std.os.linux.EPOLL.IN) != 0;
            }
        }
        return false;
    }

    inline fn isReadyWrite(self: Self, sock: Socket) bool {
        for (self.events.items) |ev| {
            if (ev.data.fd == sock.internal) {
                return (ev.events & std.os.linux.EPOLL.OUT) != 0;
            }
        }
        return false;
    }

    inline fn isFaulted(self: Self, sock: Socket) bool {
        for (self.events.items) |ev| {
            if (ev.data.fd == sock.internal) {
                return (ev.events & std.os.linux.EPOLL.ERR) != 0;
            }
        }
        return false;
    }
};

// Unix uses `poll()` syscall to wait for socket events.
// This allows an arbitrary number of sockets to be handled.
const UnixOSLogic = struct {
    const Self = @This();
    // use poll on linux

    fds: std.ArrayList(std.posix.pollfd),

    inline fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .fds = std.ArrayList(std.posix.pollfd).init(allocator),
        };
    }

    inline fn deinit(self: Self) void {
        self.fds.deinit();
    }

    inline fn clear(self: *Self) void {
        self.fds.shrinkRetainingCapacity(0);
    }

    inline fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
        // Always poll for errors as this is done anyways
        var mask: i16 = std.posix.POLL.ERR;

        if (events.read)
            mask |= std.posix.POLL.IN;
        if (events.write)
            mask |= std.posix.POLL.OUT;

        for (self.fds.items) |*pfd| {
            if (pfd.fd == sock.internal) {
                pfd.events |= mask;
                return;
            }
        }

        try self.fds.append(std.posix.pollfd{
            .fd = sock.internal,
            .events = mask,
            .revents = 0,
        });
    }

    inline fn remove(self: *Self, sock: Socket) void {
        const index = for (self.fds.items, 0..) |item, i| {
            if (item.fd == sock.internal)
                break i;
        } else null;

        if (index) |idx| {
            _ = self.fds.swapRemove(idx);
        }
    }

    inline fn checkMaskAnyBit(self: Self, sock: Socket, mask: i16) bool {
        for (self.fds.items) |item| {
            if (item.fd != sock.internal)
                continue;

            if ((item.revents & mask) != 0) {
                return true;
            }

            return false;
        }
        return false;
    }

    inline fn isReadyRead(self: Self, sock: Socket) bool {
        return self.checkMaskAnyBit(sock, std.posix.POLL.IN);
    }

    inline fn isReadyWrite(self: Self, sock: Socket) bool {
        return self.checkMaskAnyBit(sock, std.posix.POLL.OUT);
    }

    inline fn isFaulted(self: Self, sock: Socket) bool {
        return self.checkMaskAnyBit(sock, std.posix.POLL.ERR);
    }
};

/// Alias to UnixOSLogic as the logic between the two are shared and both support poll()
const DarwinOsLogic = UnixOSLogic;

// On windows, we use select()
const WindowsOSLogic = struct {
    // The windows struct fd_set uses a statically size array of 64 sockets by default.
    // However, it is documented that one can create bigger sets and pass them into the functions that use them.
    // Instead, we dynamically allocate the sets and reallocate them as needed.
    // See https://docs.microsoft.com/en-us/windows/win32/winsock/maximum-number-of-sockets-supported-2
    const FdSet = extern struct {
        padding1: c_uint = 0, // This is added to guarantee &size is 8 byte aligned
        capacity: c_uint,
        size: c_uint,
        padding2: c_uint = 0, // This is added to guarantee &fds is 8 byte aligned
        // fds: SOCKET[size]

        fn fdSlice(self: *align(8) FdSet) []windows.ws2_32.SOCKET {
            const ptr: [*]u8 = @ptrCast(self);
            const socket_ptr: [*]windows.ws2_32.SOCKET = @alignCast(@ptrCast(ptr + 4 * @sizeOf(c_uint)));
            return socket_ptr[0..self.size];
        }

        fn make(allocator: std.mem.Allocator) !*align(8) FdSet {
            // Initialize with enough space for 8 sockets.
            const mem = try allocator.alignedAlloc(u8, 8, 4 * @sizeOf(c_uint) + 8 * @sizeOf(windows.ws2_32.SOCKET));

            const fd_set: *align(8) FdSet = @ptrCast(mem);
            fd_set.* = .{ .capacity = 8, .size = 0 };
            return fd_set;
        }

        fn clear(self: *align(8) FdSet) void {
            self.size = 0;
        }

        fn memSlice(self: *align(8) FdSet) []u8 {
            const ptr: [*]u8 = @ptrCast(self);
            return ptr[0..(4 * @sizeOf(c_uint) + self.capacity * @sizeOf(windows.ws2_32.SOCKET))];
        }

        fn deinit(self: *align(8) FdSet, allocator: std.mem.Allocator) void {
            const ptr: []align(8) u8 = @alignCast(self.memSlice());
            allocator.free(ptr);
        }

        fn containsFd(self: *align(8) FdSet, fd: windows.ws2_32.SOCKET) bool {
            for (self.fdSlice()) |ex_fd| {
                if (ex_fd == fd) return true;
            }
            return false;
        }

        fn addFd(fd_set: **align(8) FdSet, allocator: std.mem.Allocator, new_fd: windows.ws2_32.SOCKET) !void {
            if (fd_set.*.size == fd_set.*.capacity) {
                // Double our capacity.
                const new_mem_size = 4 * @sizeOf(c_uint) + 2 * fd_set.*.capacity * @sizeOf(windows.ws2_32.SOCKET);
                const ptr: []u8 align(8) = @alignCast(fd_set.*.memSlice());
                fd_set.* = @alignCast(@ptrCast((try allocator.reallocAdvanced(ptr, new_mem_size, @returnAddress())).ptr));
                fd_set.*.capacity *= 2;
            }

            fd_set.*.size += 1;
            fd_set.*.fdSlice()[fd_set.*.size - 1] = new_fd;
        }

        fn getSelectPointer(self: *align(8) FdSet) ?[*]u8 {
            if (self.size == 0) return null;
            const ptr: [*]u8 = @ptrCast(self);
            return ptr + 2 * @sizeOf(c_uint);
        }
    };

    const Self = @This();

    allocator: std.mem.Allocator,

    read_fds: std.ArrayListUnmanaged(windows.ws2_32.SOCKET),
    write_fds: std.ArrayListUnmanaged(windows.ws2_32.SOCKET),

    read_fd_set: *align(8) FdSet,
    write_fd_set: *align(8) FdSet,
    except_fd_set: *align(8) FdSet,

    inline fn init(allocator: std.mem.Allocator) !Self {
        const read_fds = try std.ArrayListUnmanaged(windows.ws2_32.SOCKET).initCapacity(allocator, 8);
        const write_fds = try std.ArrayListUnmanaged(windows.ws2_32.SOCKET).initCapacity(allocator, 8);

        return Self{
            .allocator = allocator,
            .read_fds = read_fds,
            .write_fds = write_fds,
            .read_fd_set = try FdSet.make(allocator),
            .write_fd_set = try FdSet.make(allocator),
            .except_fd_set = try FdSet.make(allocator),
        };
    }

    inline fn deinit(self: *Self) void {
        self.read_fds.deinit(self.allocator);
        self.write_fds.deinit(self.allocator);

        self.read_fd_set.deinit(self.allocator);
        self.write_fd_set.deinit(self.allocator);
        self.except_fd_set.deinit(self.allocator);
    }

    inline fn clear(self: *Self) void {
        self.read_fds.shrinkRetainingCapacity(0);
        self.write_fds.shrinkRetainingCapacity(0);

        self.read_fd_set.clear();
        self.write_fd_set.clear();
        self.except_fd_set.clear();
    }

    inline fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
        if (events.read) read_block: {
            for (self.read_fds.items) |fd| {
                if (fd == sock.internal) break :read_block;
            }
            try self.read_fds.append(self.allocator, sock.internal);
        }
        if (events.write) {
            for (self.write_fds.items) |fd| {
                if (fd == sock.internal) return;
            }
            try self.write_fds.append(self.allocator, sock.internal);
        }
    }

    inline fn remove(self: *Self, sock: Socket) void {
        for (self.read_fds.items, 0..) |fd, idx| {
            if (fd == sock.internal) {
                _ = self.read_fds.swapRemove(idx);
                break;
            }
        }
        for (self.write_fds.items, 0..) |fd, idx| {
            if (fd == sock.internal) {
                _ = self.write_fds.swapRemove(idx);
                break;
            }
        }
    }

    const Set = enum {
        read,
        write,
        except,
    };

    inline fn getFdSet(self: *Self, comptime set_selection: Set) !?[*]u8 {
        const set_ptr = switch (set_selection) {
            .read => &self.read_fd_set,
            .write => &self.write_fd_set,
            .except => &self.except_fd_set,
        };

        set_ptr.*.clear();
        if (set_selection == .read or set_selection == .except) {
            for (self.read_fds.items) |fd| {
                try FdSet.addFd(set_ptr, self.allocator, fd);
            }
        }

        if (set_selection == .write) {
            for (self.write_fds.items) |fd| {
                try FdSet.addFd(set_ptr, self.allocator, fd);
            }
        } else if (set_selection == .except) {
            for (self.write_fds.items) |fd| {
                if (set_ptr.*.containsFd(fd)) continue;
                try FdSet.addFd(set_ptr, self.allocator, fd);
            }
        }
        return set_ptr.*.getSelectPointer();
    }

    inline fn isReadyRead(self: Self, sock: Socket) bool {
        if (self.read_fd_set.getSelectPointer()) |ptr| {
            return windows.funcs.__WSAFDIsSet(sock.internal, ptr) != 0;
        }
        return false;
    }

    inline fn isReadyWrite(self: Self, sock: Socket) bool {
        if (self.write_fd_set.getSelectPointer()) |ptr| {
            return windows.funcs.__WSAFDIsSet(sock.internal, ptr) != 0;
        }
        return false;
    }

    inline fn isFaulted(self: Self, sock: Socket) bool {
        if (self.except_fd_set.getSelectPointer()) |ptr| {
            return windows.funcs.__WSAFDIsSet(sock.internal, ptr) != 0;
        }
        return false;
    }
};

/// Waits until sockets in SocketSet are ready to read/write or have a fault condition.
/// If `timeout` is not `null`, it describes a timeout in nanoseconds until the function
/// should return.
/// Note that `timeout` granularity may not be available in nanoseconds and larger
/// granularities are used.
/// If the requested timeout interval requires a finer granularity than the implementation supports, the
/// actual timeout interval shall be rounded up to the next supported value.
pub fn waitForSocketEvent(set: *SocketSet, timeout: ?u64) !usize {
    switch (builtin.os.tag) {
        .windows => {
            const read_set = try set.internal.getFdSet(.read);
            const write_set = try set.internal.getFdSet(.write);
            const except_set = try set.internal.getFdSet(.except);
            if (read_set == null and write_set == null and except_set == null) return 0;

            const tm: windows.timeval = if (timeout) |tout| block: {
                const secs = @divFloor(tout, std.time.ns_per_s);
                const usecs = @divFloor(tout - secs * std.time.ns_per_s, 1000);
                break :block .{ .tv_sec = @intCast(secs), .tv_usec = @intCast(usecs) };
            } else .{ .tv_sec = 0, .tv_usec = 0 };

            // Windows ignores first argument.
            return try windows.select(0, read_set, write_set, except_set, if (timeout != null) &tm else null);
        },
        .linux => {
            // Use epoll for Linux
            set.internal.events.clearRetainingCapacity();
            const timeout_ms: i32 = if (timeout) |tout|
                @as(i32, @intCast((tout + std.time.ns_per_ms - 1) / std.time.ns_per_ms))
            else
                -1;

            // Resize events array to fit all registered sockets
            try set.internal.events.resize(set.internal.socket_map.count());

            if (set.internal.events.items.len == 0) return 0;

            var rc: usize = undefined;
            rc = std.os.linux.epoll_wait(set.internal.epoll_fd, set.internal.events.items.ptr, @intCast(set.internal.events.items.len), timeout_ms);

            if (rc > std.math.maxInt(i32)) {
                const errno = std.os.linux.E.init(rc);
                switch (errno) {
                    .INTR => return 0,
                    else => return std.posix.unexpectedErrno(errno),
                }
            }

            // A return of 0 is valid (timeout with no events)
            const event_count: usize = @truncate(rc);
            return event_count;
        },
        else => if (is_unix) {
            return try std.posix.poll(
                set.internal.fds.items,
                if (timeout) |val| @as(i32, @intCast((val + std.time.ns_per_ms - 1) / std.time.ns_per_ms)) else -1,
            );
        } else {
            @compileError("unsupported os " ++ @tagName(builtin.os.tag) ++ " for SocketSet!");
        },
    }
}

pub fn connectToHost(
    allocator: std.mem.Allocator,
    name: []const u8,
    port: u16,
    protocol: Protocol,
) !Socket {
    const endpoint_list = try getEndpointList(allocator, name, port);
    defer endpoint_list.deinit();

    for (endpoint_list.endpoints) |endpt| {
        var sock = try Socket.create(@as(AddressFamily, endpt.address), protocol);
        sock.connect(endpt) catch {
            sock.close();
            continue;
        };
        return sock;
    }

    return error.CouldNotConnect;
}

pub const EndpointList = struct {
    arena: std.heap.ArenaAllocator,
    endpoints: []EndPoint,
    canon_name: ?[]u8,

    pub fn deinit(self: *EndpointList) void {
        var arena = self.arena;
        arena.deinit();
    }
};

// Code adapted from std.net

/// Call `EndpointList.deinit` on the result.
pub fn getEndpointList(allocator: std.mem.Allocator, name: []const u8, port: u16) !*EndpointList {
    const result = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const result = try arena.allocator().create(EndpointList);
        result.* = EndpointList{
            .arena = arena,
            .endpoints = undefined,
            .canon_name = null,
        };
        break :blk result;
    };
    const arena = result.arena.allocator();
    errdefer result.arena.deinit();

    if (builtin.link_libc or is_windows) {
        const getaddrinfo_fn = if (is_windows) windows.getaddrinfo else libc_getaddrinfo;
        const freeaddrinfo_fn = if (is_windows) windows.funcs.freeaddrinfo else std.posix.system.freeaddrinfo;

        const name_c = try allocator.dupeZ(u8, name);
        defer allocator.free(name_c);

        const port_c = try std.fmt.allocPrint(allocator, "{}\x00", .{port});
        defer allocator.free(port_c);

        const hints: posix.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = posix.AF.UNSPEC,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };

        var res: ?*posix.addrinfo = undefined;
        try getaddrinfo_fn(name_c.ptr, @ptrCast(port_c.ptr), &hints, &res);
        defer if (res) |r| freeaddrinfo_fn(r);

        const addr_count = blk: {
            var count: usize = 0;
            var it: ?*posix.addrinfo = res;
            while (it) |info| : (it = info.next) {
                if (info.addr != null) {
                    count += 1;
                }
            }
            break :blk count;
        };
        result.endpoints = try arena.alloc(EndPoint, addr_count);

        var it: ?*posix.addrinfo = res;
        var i: usize = 0;
        while (it) |info| : (it = info.next) {
            const sockaddr = info.addr orelse continue;
            const addr: Address = switch (sockaddr.family) {
                std.posix.AF.INET => block: {
                    const bytes: *const [4]u8 = @ptrCast(sockaddr.data[2..]);
                    break :block .{ .ipv4 = Address.IPv4.init(bytes[0], bytes[1], bytes[2], bytes[3]) };
                },
                std.posix.AF.INET6 => block: {
                    const sockaddr_in6: *align(1) const std.posix.sockaddr.in6 = @ptrCast(sockaddr);
                    break :block .{ .ipv6 = Address.IPv6.init(sockaddr_in6.addr, sockaddr_in6.scope_id) };
                },
                else => unreachable,
            };

            result.endpoints[i] = .{
                .address = addr,
                .port = port,
            };

            if (info.canonname) |n| {
                if (result.canon_name == null) {
                    result.canon_name = try arena.dupe(u8, std.mem.sliceTo(n, 0));
                }
            }
            i += 1;
        }

        return result;
    }

    if (builtin.os.tag == .linux) {
        // Fall back to std.net
        const address_list = try std.net.getAddressList(allocator, name, port);
        defer address_list.deinit();

        if (address_list.canon_name) |cname| {
            result.canon_name = try arena.dupe(u8, cname);
        }

        const count: usize = address_list.addrs.len;

        result.endpoints = try arena.alloc(EndPoint, count);

        var idx: usize = 0;
        for (address_list.addrs) |net_addr| {
            const addr: Address = switch (net_addr.any.family) {
                std.posix.AF.INET => block: {
                    const bytes: *const [4]u8 = @ptrCast(&net_addr.in.sa.addr);
                    break :block .{ .ipv4 = Address.IPv4.init(bytes[0], bytes[1], bytes[2], bytes[3]) };
                },
                std.posix.AF.INET6 => .{ .ipv6 = Address.IPv6.init(net_addr.in6.sa.addr, net_addr.in6.sa.scope_id) },
                else => unreachable,
            };

            result.endpoints[idx] = EndPoint{
                .address = addr,
                .port = port,
            };
            idx += 1;
        }

        return result;
    }
    @compileError("unsupported os " ++ @tagName(builtin.os.tag) ++ " for getEndpointList!");
}

const GetAddrInfoError = error{
    HostLacksNetworkAddresses,
    TemporaryNameServerFailure,
    NameServerFailure,
    AddressFamilyNotSupported,
    OutOfMemory,
    UnknownHostName,
    ServiceUnavailable,
} || std.posix.UnexpectedError;

fn libc_getaddrinfo(
    name: [*:0]const u8,
    port: [*:0]const u8,
    hints: *const std.posix.addrinfo,
    result: *?*std.posix.addrinfo,
) GetAddrInfoError!void {
    const rc = std.posix.system.getaddrinfo(name, port, hints, result);
    if (rc != @as(std.posix.system.EAI, @enumFromInt(0)))
        return switch (rc) {
            .ADDRFAMILY => return error.HostLacksNetworkAddresses,
            .AGAIN => return error.TemporaryNameServerFailure,
            .BADFLAGS => unreachable, // Invalid hints
            .FAIL => return error.NameServerFailure,
            .FAMILY => return error.AddressFamilyNotSupported,
            .MEMORY => return error.OutOfMemory,
            .NODATA => return error.HostLacksNetworkAddresses,
            .NONAME => return error.UnknownHostName,
            .SERVICE => return error.ServiceUnavailable,
            .SOCKTYPE => unreachable, // Invalid socket type requested in hints
            .SYSTEM => switch (std.posix.errno(-1)) {
                else => |e| return std.posix.unexpectedErrno(e),
            },
            else => unreachable,
        };
}

const windows = struct {
    pub const CreateIoCompletionPort = std.os.windows.CreateIoCompletionPort;
    pub const DWORD = std.os.windows.DWORD;
    pub const FALSE = std.os.windows.FALSE;
    pub const kernel32 = std.os.windows.kernel32;
    pub const ULONG = std.os.windows.ULONG;
    pub const unexpectedError = std.os.windows.unexpectedError;
    pub const unexpectedWSAError = std.os.windows.unexpectedWSAError;
    pub const ws2_32 = std.os.windows.ws2_32;
    pub const WSACleanup = std.os.windows.WSACleanup;
    pub const WSASocketW = std.os.windows.WSASocketW;
    pub const WSAStartup = std.os.windows.WSAStartup;

    // Control message buffer sizes
    const CMSG_HEADER_SIZE: usize = @sizeOf(CMSGHDR);
    const PKTINFOV4_DATA_SIZE: usize = @sizeOf(IN_PKTINFO);
    const PKTINFOV6_DATA_SIZE: usize = @sizeOf(IN6_PKTINFO);
    const CONTROL_PKTINFOV4_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFOV4_DATA_SIZE;
    const CONTROL_PKTINFOV6_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFOV6_DATA_SIZE + 8; // Add padding

    // Windows-specific structures
    // These structures aren't available in std.os.windows.ws2_32
    // Based on Windows SDK headers and the rust-lang/socket-pktinfo implementation
    const CMSGHDR = extern struct {
        cmsg_len: usize,
        cmsg_level: i32,
        cmsg_type: i32,
    };

    // Use a flat structure for IN_PKTINFO to make it extern-compatible
    const IN_PKTINFO = extern struct {
        ipi_addr_s_addr: u32, // Equivalent to S_un.S_addr
        ipi_ifindex: u32,
    };

    // Use a flat structure for IN6_PKTINFO to make it extern-compatible
    const IN6_PKTINFO = extern struct {
        ipi6_addr: [16]u8, // Equivalent to u.Byte
        ipi6_ifindex: u32,
    };

    const IN_ADDR = extern struct {
        s_addr: u32,
    };

    const ip_mreq = extern struct {
        imr_multiaddr: IN_ADDR,
        imr_interface: IN_ADDR,
    };

    const timeval = extern struct {
        tv_sec: c_long,
        tv_usec: c_long,
    };

    // Use standard library definitions where available
    const WSABUF = ws2_32.WSABUF;
    const WSAMSG = ws2_32.WSAMSG;

    // Socket option constants from standard library
    const IP_PKTINFO: i32 = ws2_32.IP_PKTINFO;
    const IPV6_PKTINFO: i32 = ws2_32.IPV6_PKTINFO;
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = ws2_32.SIO_GET_EXTENSION_FUNCTION_POINTER;

    // Extensions function ID
    const LPFN_WSARECVMSG = ws2_32.LPFN_WSARECVMSG;
    const WSAID_WSARECVMSG = ws2_32.WSAID_WSARECVMSG;

    const funcs = struct {
        extern "ws2_32" fn recvfrom(s: ws2_32.SOCKET, buf: [*c]u8, len: c_int, flags: c_int, from: [*c]std.posix.sockaddr, fromlen: [*c]std.posix.socklen_t) callconv(std.os.windows.WINAPI) c_int;
        extern "ws2_32" fn select(nfds: c_int, readfds: ?*anyopaque, writefds: ?*anyopaque, exceptfds: ?*anyopaque, timeout: [*c]const timeval) callconv(std.os.windows.WINAPI) c_int;
        extern "ws2_32" fn __WSAFDIsSet(arg0: ws2_32.SOCKET, arg1: [*]u8) c_int;
        extern "ws2_32" fn getaddrinfo(nodename: [*:0]const u8, servicename: [*:0]const u8, hints: *const posix.addrinfo, result: **posix.addrinfo) callconv(std.os.windows.WINAPI) c_int;
        extern "ws2_32" fn freeaddrinfo(res: *posix.addrinfo) callconv(std.os.windows.WINAPI) void;
    };

    // TODO: This can be removed in favor of upstream Zig `std.posix.socket` if the
    // `std.posix.socket` implementation handles `std.posix.SOCK.DGRAM`.
    fn socket(addr_family: u32, socket_type: u32, protocol: u32) std.posix.SocketError!ws2_32.SOCKET {
        const sock = try WSASocketW(
            @intCast(addr_family),
            @intCast(socket_type),
            @intCast(protocol),
            null,
            0,
            ws2_32.WSA_FLAG_OVERLAPPED,
        );

        // Disable SIO_UDP_CONNRESET behaviour for UDP
        //
        // This resolves an issue where "recvfrom" can return a WSAECONNRESET error if a previous send
        // call failed and resulted in an ICMP Port Unreachable message.
        // https://github.com/ikskuh/zig-network/issues/66
        if (socket_type == std.posix.SOCK.DGRAM) {
            // This was based off the following Go code:
            // https://github.com/golang/go/blob/5c154986094bcc2fb28909cc5f01c9ba1dd9ddd4/src/internal/poll/fd_windows.go#L338
            const IOC_IN = 0x80000000;
            const IOC_VENDOR = 0x18000000;
            const SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;
            const flag = &[_]u8{ 0, 0, 0, 0 };
            var ret: u32 = 0;
            switch (ws2_32.WSAIoctl(sock, SIO_UDP_CONNRESET, flag.ptr, flag.len, null, 0, &ret, null, null)) {
                0 => {},
                ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
                    else => |err| return unexpectedWSAError(err),
                },
                else => unreachable,
            }
        }

        return sock;
    }

    // NOTE: The `recvfrom` implementation in upstream Zig `std` is marked as
    // an `extern "c"` function, and thus replacing the below implementation
    // causes Windows to require linking `libc`.
    fn recvfrom(
        sock: ws2_32.SOCKET,
        buf: []u8,
        flags: u32,
        src_addr: ?*std.posix.sockaddr,
        addrlen: ?*std.posix.socklen_t,
    ) std.posix.RecvFromError!usize {
        while (true) {
            const result = funcs.recvfrom(sock, buf.ptr, @intCast(buf.len), @intCast(flags), src_addr, addrlen);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAEISCONN => unreachable,
                    .WSAENOTSOCK => unreachable,
                    .WSAESHUTDOWN => unreachable,
                    .WSAEOPNOTSUPP => unreachable,
                    .WSAETIMEDOUT, .WSAEWOULDBLOCK => error.WouldBlock,
                    .WSAEINTR => continue,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return @intCast(result);
        }
    }

    pub const SelectError = error{FileDescriptorNotASocket} || std.posix.UnexpectedError;

    fn select(nfds: usize, read_fds: ?[*]u8, write_fds: ?[*]u8, except_fds: ?[*]u8, timeout: ?*const timeval) SelectError!usize {
        _ = nfds;
        while (true) {
            // Windows ignores nfds so we just pass zero here.
            const result = funcs.select(0, read_fds, write_fds, except_fds, timeout);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAEINTR => continue,
                    .WSAENOTSOCK => error.FileDescriptorNotASocket,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return @intCast(result);
        }
    }

    fn getaddrinfo(
        name: [*:0]const u8,
        port: [*:0]const u8,
        hints: *const posix.addrinfo,
        result: *?*posix.addrinfo,
    ) GetAddrInfoError!void {
        const rc = funcs.getaddrinfo(name, port, hints, @ptrCast(result));
        if (rc != 0)
            return switch (ws2_32.WSAGetLastError()) {
                .WSATRY_AGAIN => error.TemporaryNameServerFailure,
                .WSAEINVAL => unreachable,
                .WSANO_RECOVERY => error.NameServerFailure,
                .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
                .WSA_NOT_ENOUGH_MEMORY => error.OutOfMemory,
                .WSAHOST_NOT_FOUND => error.UnknownHostName,
                .WSATYPE_NOT_FOUND => error.ServiceUnavailable,
                .WSAESOCKTNOSUPPORT => unreachable,
                else => |err| return unexpectedWSAError(err),
            };
    }

    /// Locate the WSARecvMsg extension function
    fn locateWsaRecvMsg(skt: std.posix.socket_t) !LPFN_WSARECVMSG {
        var fn_pointer: usize = 0;
        var byte_len: u32 = 0;

        // Get the function pointer using WSAIoctl
        const r = windows.ws2_32.WSAIoctl(
            skt,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            @constCast(@ptrCast(&WSAID_WSARECVMSG)),
            @sizeOf(@TypeOf(WSAID_WSARECVMSG)),
            @ptrCast(&fn_pointer),
            @sizeOf(@TypeOf(fn_pointer)),
            &byte_len,
            null,
            null,
        );

        if (r != 0) return error.ExtensionFunctionNotFound;

        if (@sizeOf(usize) != byte_len)
            return error.InvalidExtensionFunction;

        // Convert the usize to a function pointer
        const ptr: *anyopaque = @ptrFromInt(fn_pointer);
        const cast_fn: LPFN_WSARECVMSG = @ptrCast(ptr);

        // We can't check if cast_fn is null since it's not an optional pointer
        // Just return the function pointer
        return cast_fn;
    }

    pub fn recvmsg(skt: *Socket, data: []u8, flags: u32) !RecvMsgResult {
        const recvmsg_fn = try locateWsaRecvMsg(skt.internal);

        // Prepare address storage for the sender
        var addr_storage: std.posix.sockaddr.storage = undefined;
        const addr_len: i32 = @sizeOf(@TypeOf(addr_storage));

        // Prepare control message buffer based on socket family
        var control_buffer: [256]u8 = undefined;

        // Create the WSA buffer for data
        var wsa_buf = WSABUF{
            .len = @intCast(data.len),
            .buf = data.ptr,
        };

        // Create the WSA message structure
        var wsa_msg = WSAMSG{
            .name = @ptrCast(&addr_storage),
            .namelen = addr_len,
            .lpBuffers = @ptrCast(&wsa_buf),
            .dwBufferCount = 1,
            .Control = WSABUF{
                .len = @intCast(control_buffer.len),
                .buf = &control_buffer,
            },
            .dwFlags = @intCast(flags),
        };

        // Call WSARecvMsg
        var bytes_received: u32 = 0;
        const result = recvmsg_fn(
            skt.internal,
            &wsa_msg,
            &bytes_received,
            null,
            null,
        );

        if (result != 0) {
            const err = windows.ws2_32.WSAGetLastError();
            switch (err) {
                .WSAEMSGSIZE => return error.MessageTooLong,
                .WSAEWOULDBLOCK => return error.WouldBlock,
                .WSAEFAULT => unreachable,
                .WSAEINVAL => unreachable,
                .WSAEINTR => return error.Interrupted,
                .WSAETIMEDOUT => return error.ConnectionTimedOut,
                else => return error.NetworkSubsystemFailed,
            }
        }

        if (bytes_received == 0) {
            return error.ConnectionClosed;
        }

        // Process control messages to extract packet info
        var pkt_info: PktInfo = undefined;
        var pkt_info_found = false;

        // Get source address from the sender
        const src_addr = try EndPoint.fromSocketAddress(@ptrCast(wsa_msg.name), @intCast(wsa_msg.namelen));
        pkt_info.addr_src = EndPoint{
            .address = src_addr.address,
            .port = src_addr.port,
        };

        // Process control messages to extract destination address and interface
        var cmsg_ptr: [*]u8 = &control_buffer;
        var control_len = wsa_msg.Control.len;

        while (control_len >= @sizeOf(CMSGHDR)) {
            const cmsg: *CMSGHDR = @ptrCast(@alignCast(cmsg_ptr));

            if (cmsg.cmsg_len < @sizeOf(CMSGHDR)) {
                break;
            }

            if (skt.family == .ipv4 and
                cmsg.cmsg_level == ws2_32.IPPROTO.IP and
                cmsg.cmsg_type == IP_PKTINFO)
            {
                if (cmsg.cmsg_len >= @sizeOf(CMSGHDR) + @sizeOf(IN_PKTINFO)) {
                    const info: *IN_PKTINFO = @ptrCast(@alignCast(cmsg_ptr + @sizeOf(CMSGHDR)));

                    pkt_info.if_index = info.ipi_ifindex;
                    pkt_info.addr_dst = Address{ .ipv4 = .{ .value = @bitCast(info.ipi_addr_s_addr) } };

                    pkt_info_found = true;
                }
            } else if (skt.family == .ipv6 and
                cmsg.cmsg_level == ws2_32.IPPROTO.IP and
                cmsg.cmsg_type == IPV6_PKTINFO)
            {
                if (cmsg.cmsg_len >= @sizeOf(CMSGHDR) + @sizeOf(IN6_PKTINFO)) {
                    const info: *IN6_PKTINFO = @ptrCast(@alignCast(cmsg_ptr + @sizeOf(CMSGHDR)));

                    pkt_info.if_index = info.ipi6_ifindex;
                    pkt_info.addr_dst = Address{
                        .ipv6 = .{
                            .value = info.ipi6_addr,
                            .scope_id = 0,
                        },
                    };

                    pkt_info_found = true;
                }
            }

            // Move to next control message
            const next_offset = std.mem.alignForward(usize, cmsg.cmsg_len, 8); // Align to 8 bytes
            cmsg_ptr += next_offset;
            if (control_len < next_offset) {
                break;
            }
            control_len -= @intCast(next_offset);
        }

        if (!pkt_info_found) {
            return error.NoPktInfo;
        }

        return RecvMsgResult{
            .info = pkt_info,
            .bytes_received = bytes_received,
        };
    }

    pub fn joinMulticastGroup(self: std.posix.socket_t, group: Socket.MulticastGroup) !void {
        // https://learn.microsoft.com/en-us/windows/win32/winsock/multicast-programming-sample
        // https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ip_mreq_source
        // https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ip_mreq
        //
        // Note that `IP_ADD_MEMBERSHIP` is from `IGMPv2` to receive any multicast
        // without specifying the source address.
        // `IP_ADD_SOURCE_MEMBERSHIP` is from `IGMPv3` to receive multicast from a specific source.
        const request = ip_mreq{
            .imr_multiaddr = IN_ADDR{ .s_addr = @bitCast(group.group.value) },
            .imr_interface = IN_ADDR{ .s_addr = @bitCast(group.interface.value) },
        };

        try std.posix.setsockopt(
            self,
            std.os.windows.ws2_32.IPPROTO.IP,
            std.os.windows.ws2_32.IP_ADD_MEMBERSHIP,
            std.mem.asBytes(&request),
        );
        return;
    }
};

// ************* recvmsg *************

// https://github.com/pixsper/socket-pktinfo
// https://github.com/pixsper/socket-pktinfo/blob/main/src/unix.rs
// https://github.com/pixsper/socket-pktinfo/blob/main/src/win.rs

// https://man7.org/linux/man-pages/man7/ip.7.html
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/musl/include/netinet/in.h#L301-L305

// https://github.com/search?q=repo%3Arust-lang%2Flibc%20cmsghdr&type=code
// https://github.com/search?q=repo%3Aziglang%2Fzig%20cmsghdr&type=code

// https://stackoverflow.com/questions/4412749/are-flexible-array-members-valid-in-c
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/generic-glibc/bits/socket.h#L265-L295
// Structure describing messages sent by `sendmsg' and received by `recvmsg'

// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/generic-glibc/scsi/sg.h#L33-L41
// https://ziglang.org/documentation/master/std/#std.posix.iovec

// `recvmsg`
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/recvmsg.2.html
// https://man.freebsd.org/cgi/man.cgi?recvmsg(2)
// https://man7.org/linux/man-pages/man3/cmsg.3.html

// CMSG definitions
// musl
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/musl/include/sys/socket.h#L352-L364
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/musl/src/network/recvmsg.c#L20
// generic libc
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/generic-glibc/bits/socket.h#L282-L317
// rust
// https://github.com/rust-lang/libc/blob/main/libc-test/test/cmsg.rs
// macOS
// https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/any-macos-any/sys/socket.h#L600-L611

const unix = struct {
    const iovec = std.posix.iovec;
    // Use linux.msghdr directly like mini.zig does
    const msghdr = std.posix.msghdr;

    const in_addr = extern struct {
        s_addr: u32,
    };
    const in_pktinfo = extern struct {
        ipi_ifindex: u32,
        ipi_spec_dst: in_addr,
        ipi_addr: in_addr,
    };

    const in6_addr = extern struct {
        s6_addr: [16]u8,
    };
    const in6_pktinfo = extern struct {
        ipi6_addr: in6_addr,
        ipi6_ifindex: u32,
    };
    // there's no `recvmsg` in `bsd` predefined in `std.posix`
    // https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/any-macos-any/sys/socket.h#L600-L611
    // I bet the `recvmsg` implementation in `bsd` is the same as `linux`
    // note that std.c is for `solaris` and `illumos`

    fn CMSG_HDR_TYPE() type {
        return if (comptime is_bsd) {
            return extern struct {
                len: std.posix.socklen_t,
                level: c_int,
                type: c_int,
            };
        } else {
            // musl implementation
            return if (@sizeOf(usize) > 4)
                if (builtin.target.cpu.arch.endian() == .big)
                    extern struct {
                        __pad1: c_int,
                        len: std.posix.socklen_t,
                        level: c_int,
                        type: c_int,
                    }
                else
                    extern struct {
                        len: std.posix.socklen_t,
                        __pad1: c_int,
                        level: c_int,
                        type: c_int,
                    }
            else
                extern struct {
                    len: std.posix.socklen_t,
                    level: c_int,
                    type: c_int,
                };
        };
    }

    const cmsghdr = CMSG_HDR_TYPE();

    fn CMSG_ALIGN(len: usize) usize {
        return std.mem.alignForward(usize, len, @sizeOf(usize));
    }

    fn CMSG_LEN(len: usize) usize {
        return CMSG_ALIGN(@sizeOf(cmsghdr)) + len;
    }

    fn CMSG_SPACE(len: usize) usize {
        return CMSG_ALIGN(len) + CMSG_ALIGN(@sizeOf(cmsghdr));
    }

    fn CMSG_DATA(cmsg: *const cmsghdr) [*]u8 {
        const ptr: [*]const u8 = @ptrCast(cmsg);
        return @ptrCast(@constCast(ptr + @sizeOf(cmsghdr)));
    }

    fn __CMSG_LEN(cmsg: *const cmsghdr) usize {
        return std.mem.alignForward(usize, cmsg.len, @sizeOf(usize));
    }

    fn __CMSG_NEXT(cmsg: *const cmsghdr) [*]u8 {
        const ptr: [*]const u8 = @ptrCast(cmsg);
        return @ptrCast(@constCast(ptr + __CMSG_LEN(cmsg)));
    }

    fn __MHDR_END(mhdr: *const msghdr) [*]u8 {
        const ptr: [*]const u8 = @ptrCast(mhdr.control);
        return @ptrCast(@constCast(ptr + mhdr.controllen));
    }

    fn CMSG_FIRSTHDR(mhdr: *const msghdr) ?*cmsghdr {
        if (mhdr.controllen >= @sizeOf(cmsghdr)) {
            return @ptrCast(@alignCast(mhdr.control));
        }
        return null;
    }

    fn CMSG_NXTHDR(mhdr: *const msghdr, cmsg: *const cmsghdr) ?*cmsghdr {
        if (cmsg.len < @sizeOf(cmsghdr)) {
            return null;
        }

        const next = __CMSG_NEXT(cmsg);
        const end = __MHDR_END(mhdr);

        if (@intFromPtr(next) + @sizeOf(cmsghdr) > @intFromPtr(end)) {
            return null;
        }

        return @ptrCast(@alignCast(next));
    }

    pub fn recvmsg(sock: *Socket, buffer: []u8, flags: u32) RecvMsgError!RecvMsgResult {
        const MAX_CONTROL_BUFFER_SIZE = @sizeOf(cmsghdr) + 1024;
        var cmsg_buf: [MAX_CONTROL_BUFFER_SIZE]u8 = undefined;
        var src_addr: std.posix.sockaddr.storage = undefined;
        var iov = iovec{
            .base = buffer.ptr,
            .len = buffer.len,
        };
        // we need to init `msghdr` explicitly, instead of leave it undefined
        // otherwise Linux kernel doesn't like it
        var msg = msghdr{
            .name = @ptrCast(&src_addr),
            .namelen = @sizeOf(std.posix.sockaddr.storage),
            .iov = @ptrCast(&iov),
            .iovlen = 1,
            .control = &cmsg_buf,
            .controllen = cmsg_buf.len,
            .flags = 0,
        };

        var rc: isize = undefined;
        if (comptime is_linux) {
            rc = @bitCast(std.os.linux.recvmsg(sock.internal, &msg, flags));
        } else if (comptime is_bsd) {
            rc = std.c.recvmsg(sock.internal, &msg, flags);
        } else {
            @compileError("Unsupported OS: " ++ @tagName(builtin.os.tag));
        }
        if (rc < 0) {
            const errno = std.posix.errno(rc);
            switch (errno) {
                .BADF => unreachable,
                .FAULT => unreachable,
                .INVAL => unreachable,
                .NOTCONN => return error.SocketNotConnected,
                .MSGSIZE => return error.MessageTooLong,
                .NOTSOCK => unreachable,
                .INTR => return error.Interrupted,
                .AGAIN => return error.WouldBlock,
                .NOMEM => return error.SystemResources,
                .CONNREFUSED => return error.ConnectionRefused,
                .CONNRESET => return error.ConnectionResetByPeer,
                .TIMEDOUT => return error.ConnectionTimedOut,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
        const bytes_recv: usize = @intCast(rc);

        var is_found_pktinfo = false;
        var pkt_info: PktInfo = undefined;

        var cmsg = unix.CMSG_FIRSTHDR(&msg);
        const IP_PKTINFO = if (is_linux) std.os.linux.IP.PKTINFO else 26;
        const IPV6_PKTINFO = if (is_linux) std.os.linux.IPV6.PKTINFO else 46;

        while (cmsg != null) : (cmsg = unix.CMSG_NXTHDR(&msg, cmsg.?)) {
            const hdr = cmsg.?;

            if (sock.family == .ipv4 and
                hdr.level == std.posix.IPPROTO.IP and
                hdr.type == IP_PKTINFO)
            {
                const info: *unix.in_pktinfo = @ptrCast(@alignCast(unix.CMSG_DATA(hdr)));
                pkt_info.if_index = info.ipi_ifindex;

                const src_addr_ep = try EndPoint.fromSocketAddress(@ptrCast(msg.name), msg.namelen);
                const dst_addr = Address{ .ipv4 = .{ .value = @bitCast(info.ipi_addr.s_addr) } };
                pkt_info.addr_dst = dst_addr;

                pkt_info.addr_src = EndPoint{
                    .address = src_addr_ep.address,
                    .port = src_addr_ep.port,
                };

                is_found_pktinfo = true;
                break;
            } else if (sock.family == .ipv6 and
                hdr.level == std.posix.IPPROTO.IPV6 and
                hdr.type == IPV6_PKTINFO)
            {
                const info: *unix.in6_pktinfo = @ptrCast(@alignCast(unix.CMSG_DATA(hdr)));
                pkt_info.if_index = info.ipi6_ifindex;

                const src_addr_ep = try EndPoint.fromSocketAddress(@ptrCast(msg.name), msg.namelen);
                const dst_addr = Address{ .ipv6 = .{ .value = info.ipi6_addr.s6_addr, .scope_id = 0 } };
                pkt_info.addr_dst = dst_addr;

                pkt_info.addr_src = EndPoint{
                    .address = src_addr_ep.address,
                    .port = src_addr_ep.port,
                };

                is_found_pktinfo = true;
                break;
            }
        }

        if (!is_found_pktinfo) {
            return error.NoPktInfo;
        }
        return RecvMsgResult{ .info = pkt_info, .message = buffer[0..bytes_recv] };
    }

    pub fn setSockOptIpPktInfo(sock: *Socket) SetSockOptError!void {
        if (sock.family == .ipv4) {
            const on: c_int = 1;
            // https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/any-macos-any/netinet/in.h#L433-L434
            const IP_PKTINFO_BSD = 26;
            const IP_PKTINFO = if (is_linux) std.os.linux.IP.PKTINFO else IP_PKTINFO_BSD;
            try std.posix.setsockopt(
                sock.internal,
                std.posix.IPPROTO.IP,
                IP_PKTINFO,
                std.mem.asBytes(&on),
            );
        } else if (sock.family == .ipv6) {
            const on: c_int = 1;
            // https://github.com/ziglang/zig/blob/d590b87b6f6d87c5cf58fbc70e3094ece754ec31/lib/libc/include/any-macos-any/netinet6/in6.h#L456
            const IPV6_RECVPKTINFO_BSD = 61;
            const IPV6_RECVPKTINFO = if (is_linux) std.os.linux.IPV6.RECVPKTINFO else IPV6_RECVPKTINFO_BSD;
            try std.posix.setsockopt(
                sock.internal,
                std.posix.IPPROTO.IPV6,
                IPV6_RECVPKTINFO,
                std.mem.asBytes(&on),
            );
        }
    }
};

pub const PktInfo = struct {
    if_index: u64, // network interface index
    addr_src: EndPoint, // equivalent `std::net::IpAddr` in Rust
    addr_dst: Address, // equivalent `std::net::SocketAddr` in Rust
};

const AddressFamilyError = error{
    UnsupportedAddressFamily,
};

const RecvMsgError = std.posix.RecvFromError || error{
    NoPktInfo,
    Interrupted,
    InsufficientBytes,
    UnsupportedAddressFamily,
    ExtensionFunctionNotFound,
    InvalidExtensionFunction,
    ConnectionClosed,
    MessageTooLong,
};
const SetSockOptError = std.posix.SetSockOptError || AddressFamilyError;

pub const RecvMsgResult = struct { info: PktInfo, message: []const u8 };

pub fn setSockOptIpPktInfo(sock: *Socket) SetSockOptError!void {
    if (builtin.os.tag == .windows) {
        const on: c_int = 1;
        if (sock.family == .ipv4) {
            try std.posix.setsockopt(
                sock.internal,
                std.os.windows.ws2_32.IPPROTO.IP,
                windows.IP_PKTINFO,
                std.mem.asBytes(&on),
            );
        } else if (sock.family == .ipv6) {
            try std.posix.setsockopt(
                sock.internal,
                std.os.windows.ws2_32.IPPROTO.IP,
                windows.IPV6_PKTINFO,
                std.mem.asBytes(&on),
            );
        }
    } else {
        return unix.setSockOptIpPktInfo(sock);
    }
}

pub inline fn recvmsg(sock: *Socket, data: []u8, flags: u32) RecvMsgError!RecvMsgResult {
    if (comptime is_windows) {
        return windows.recvmsg(sock, data, flags);
    } else {
        return unix.recvmsg(sock, data, flags);
    }
}

test "CMSG macros" {
    const testing = std.testing;

    // Test CMSG_ALIGN
    try testing.expectEqual(@as(usize, 8), unix.CMSG_ALIGN(1));
    try testing.expectEqual(@as(usize, 8), unix.CMSG_ALIGN(8));
    try testing.expectEqual(@as(usize, 16), unix.CMSG_ALIGN(9));

    // Test CMSG_LEN
    const cmsghdr_size = @sizeOf(unix.cmsghdr);
    const aligned_cmsg_size = unix.CMSG_ALIGN(cmsghdr_size);
    try testing.expectEqual(aligned_cmsg_size + 0, unix.CMSG_LEN(0));
    try testing.expectEqual(aligned_cmsg_size + 4, unix.CMSG_LEN(4));

    // Test CMSG_SPACE
    try testing.expectEqual(unix.CMSG_ALIGN(0) + aligned_cmsg_size, unix.CMSG_SPACE(0));
    try testing.expectEqual(unix.CMSG_ALIGN(4) + aligned_cmsg_size, unix.CMSG_SPACE(4));

    // Create a buffer large enough for a control message
    var buffer: [256]u8 = undefined;

    // Create a message header
    var msg: unix.msghdr = undefined;
    msg.control = &buffer;
    msg.controllen = buffer.len;

    // Test CMSG_FIRSTHDR
    const first_hdr = unix.CMSG_FIRSTHDR(&msg);
    try testing.expect(first_hdr != null);

    // Initialize the first header
    if (first_hdr) |hdr| {
        hdr.len = @intCast(unix.CMSG_LEN(4));
        hdr.level = 1;
        hdr.type = 2;

        // Get data pointer and write some data
        const data_ptr = unix.CMSG_DATA(hdr);
        data_ptr[0] = 0xAA;
        data_ptr[1] = 0xBB;
        data_ptr[2] = 0xCC;
        data_ptr[3] = 0xDD;

        // Test CMSG_NXTHDR
        msg.controllen = hdr.len;
        const next_hdr = unix.CMSG_NXTHDR(&msg, hdr);
        try testing.expect(next_hdr == null); // Should be null since we only have one header

        // Test with enough space for another header
        msg.controllen = buffer.len;
        const next_hdr2 = unix.CMSG_NXTHDR(&msg, hdr);
        try testing.expect(next_hdr2 != null);

        // Test __CMSG_LEN and __CMSG_NEXT
        const len = unix.__CMSG_LEN(hdr);
        try testing.expect(len >= hdr.len);
        try testing.expect(len % @sizeOf(usize) == 0); // Should be aligned

        const next_ptr = unix.__CMSG_NEXT(hdr);
        try testing.expect(@intFromPtr(next_ptr) > @intFromPtr(hdr));
        try testing.expect(@intFromPtr(next_ptr) == @intFromPtr(hdr) + len);
    }
}

test "Windows CMSG structures" {
    if (!is_windows) return;

    const testing = std.testing;

    // Test the size of control message buffer
    try testing.expectEqual(@sizeOf(windows.CMSGHDR), windows.CMSG_HEADER_SIZE);

    // Test buffer sizes
    const pktinfov4_buffer_size = windows.CONTROL_PKTINFOV4_BUFFER_SIZE;
    try testing.expect(pktinfov4_buffer_size >= @sizeOf(windows.CMSGHDR) + @sizeOf(windows.IN_PKTINFO));

    const pktinfov6_buffer_size = windows.CONTROL_PKTINFOV6_BUFFER_SIZE;
    try testing.expect(pktinfov6_buffer_size >= @sizeOf(windows.CMSGHDR) + @sizeOf(windows.IN6_PKTINFO));

    // Create a fake IPv4 packet info for testing
    const ipv4_pktinfo = windows.IN_PKTINFO{
        .ipi_addr_s_addr = 0x0100007F, // 127.0.0.1
        .ipi_ifindex = 1,
    };

    try testing.expectEqual(@as(u32, 0x0100007F), ipv4_pktinfo.ipi_addr_s_addr);
    try testing.expectEqual(@as(u32, 1), ipv4_pktinfo.ipi_ifindex);

    // Create a fake IPv6 packet info for testing
    const ipv6_pktinfo = windows.IN6_PKTINFO{
        .ipi6_addr = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, // ::1
        .ipi6_ifindex = 1,
    };

    try testing.expectEqual(@as(u32, 1), ipv6_pktinfo.ipi6_ifindex);
    try testing.expectEqual(@as(u8, 1), ipv6_pktinfo.ipi6_addr[15]);
}
