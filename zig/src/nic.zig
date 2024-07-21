const std = @import("std");
const os = std.os;
const posix = std.posix;
const builtin = @import("builtin");
const dbg = builtin.mode == .Debug;

pub const NICError = error{
    IoctlFailed,
    NotFound,
} || anyerror;

pub fn getNIC(ifindex: u8) NICError!*posix.ifreq {
    const SIOCGIFNAME = 0x8910;
    const sock = try posix.socket(os.linux.PF.PACKET, posix.SOCK.RAW, posix.IPPROTO.RAW);
    var ifr: posix.ifreq = std.mem.zeroes(posix.ifreq);
    ifr.ifru.ivalue = ifindex;
    if (os.linux.ioctl(sock, SIOCGIFNAME, @intFromPtr(&ifr)) < 0) {
        return NICError.IoctlFailed;
    }
    // if interface name is not set:
    if (std.mem.eql(u8, &ifr.ifrn.name, &[_]u8{0x0} ** posix.IFNAMESIZE)) {
        return NICError.NotFound;
    }
    return &ifr;
}

pub fn getNICList() NICError![15][posix.IFNAMESIZE]u8 {
    const stderr = std.io.getStdErr().writer();
    var NicList: [15][posix.IFNAMESIZE]u8 = undefined;
    for (1..15) |ifindex| {
        if (getNIC(@intCast(ifindex))) |ifr| {
            NicList[ifindex - 1] = ifr.ifrn.name;
        } else |err| {
            if (dbg) {
                switch (err) {
                    NICError.IoctlFailed => {
                        if (dbg) {
                            try stderr.print("ioctl failed..\n", .{});
                        }
                    },
                    NICError.NotFound => {
                        try stderr.print("ifindex incorrect.\n", .{});
                    },
                    else => std.debug.print("{}", .{err}),
                }
            }
            return NicList;
        }
    }
    return NicList;
}
