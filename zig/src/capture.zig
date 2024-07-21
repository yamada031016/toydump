const std = @import("std");
const os = std.os;
const posix = std.posix;

const SIOCGIFFLAGS = 0x8913;
const SIOCSIFFLAGS = 0x8914;
const SIOCGIFINDEX = 0x8933;

const ETH = enum(u16) {
    ALL = 0x0003,
    LOOP = 0x0060,
    IP = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
};

const IFF = enum(u32) {
    UP = 1 << 0,
    BROADCAST = 1 << 1,
    DEBUG = 1 << 2,
    LOOPBACK = 1 << 3,
    PROMISC = 1 << 8,
};

pub const Capture = struct {
    const This = @This();

    sock: posix.socket_t,
    ifreq: posix.ifreq,
    sa: posix.sockaddr.ll,
    nic: []const u8,

    pub fn init(nicName: []const u8, promiscFlag: bool, ipOnly: bool) !*This {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var cap = try gpa.allocator().create(This);
        errdefer cap.deinit();

        const target = if (ipOnly) @byteSwap(@intFromEnum(ETH.IP)) else @byteSwap(@intFromEnum(ETH.ALL));
        cap.sock = try posix.socket(os.linux.PF.PACKET, posix.SOCK.RAW, posix.IPPROTO.RAW);

        cap.nic = nicName;

        cap.ifreq.ifrn.name = typeConversion: {
            var tmp: [os.linux.IFNAMESIZE]u8 = undefined;
            for (cap.nic, 0..) |char, i| {
                tmp[i] = char;
            } else {
                // null-terminated.
                tmp[cap.nic.len] = 0;
            }
            break :typeConversion tmp;
        };

        cap.ifreq.ifru.ivalue = 0;
        try cap._ioctl(SIOCGIFINDEX);

        cap.sa.family = os.linux.PF.PACKET;
        cap.sa.protocol = target;
        cap.sa.ifindex = cap.ifreq.ifru.ivalue;

        try posix.bind(cap.sock, @ptrCast(&cap.sa), @sizeOf(posix.sockaddr.ll));

        if (promiscFlag) {
            try cap._ioctl(SIOCGIFFLAGS);
            cap.ifreq.ifru.flags |= @intCast(@intFromEnum(IFF.PROMISC));
            try cap._ioctl(SIOCSIFFLAGS);
        }

        return cap;
    }

    pub fn deinit(this: *This) void {
        _ = this;
    }

    fn _ioctl(this: *This, request: u32) !void {
        switch (request) {
            SIOCGIFFLAGS, SIOCSIFFLAGS => {
                if (os.linux.ioctl(this.sock, request, @intFromPtr(&this.ifreq)) < 0) {
                    unreachable;
                }
            },
            SIOCGIFINDEX => try posix.ioctl_SIOCGIFINDEX(this.sock, &this.ifreq),
            else => unreachable,
        }
    }
};
