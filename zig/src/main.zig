const std = @import("std");
const os = std.os;
const nic = @import("nic.zig");
const pcapFile = @import("pcap.zig").pcapFile;
const Capture = @import("capture.zig").Capture;

fn help() !noreturn {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("toydump version {}.{}.{}\n", .{ 0, 0, 1 });
    try stdout.print("Capture and analyze network packet.\n", .{});
    try stdout.print("\nUsage: toydump [options]...\n\n", .{});
    try stdout.print("Capture options:\n", .{});
    try stdout.print("  -i <interface>\n\tspecify NIC name\n", .{});
    try stdout.print("Others:\n", .{});
    try stdout.print("  -h\tdisplay this help message.\n", .{});
    os.exit(1);
}

const Options = struct {
    const Self = @This();
    args: [][:0]u8,

    pub fn init(self: *Self, args: [][:0]u8) !void {
        self.args = args;
    }
};

pub fn main() !void {
    const alc = std.heap.page_allocator;
    const args = try std.process.argsAlloc(alc);
    defer std.process.argsFree(alc, args);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var nicName: []const u8 = undefined;
    var filePath: []const u8 = undefined;
    var promiscFlag = true;
    var buf = [_]u8{0} ** 65535;

    if (args.len < 2) {
        filePath = "test.pcap";
        // choose default Ethernet Interface.
        const nicList = try nic.getNICList();
        // nicList[0] is always LOOPBACK,
        // nicList[1] is almost Ethernet.
        // [16]u8 -> []const u8
        nicName = &nicList[1];

        _ = try stdout.write("\x1b[35m");
        try stdout.print("NIC:\t{s}\n", .{nicName});
        _ = try stdout.write("\x1b[0m");
    }

    var needsArg = false;
    var opt: u8 = undefined;
    for (args[1..]) |value| {
        switch (value[0]) {
            '-' => {
                if (needsArg) {
                    try stderr.print("missing option argument\n", .{});
                }
                switch (value[1]) {
                    'h' => try help(),
                    'p' => promiscFlag = false,
                    else => {
                        // opt which needs argument.
                        opt = value[1];
                        needsArg = true;
                    },
                }
            },
            else => {
                if (needsArg) {
                    switch (opt) {
                        'w' => {
                            if (std.mem.containsAtLeast(u8, value, 1, ".pcap")) {
                                try stdout.print("this file is pcap!\n", .{});
                                filePath = value;
                            } else {
                                @panic("This file is not pcap format!");
                            }
                        },
                        'i' => nicName = value,
                        'p' => promiscFlag = false,
                        else => {
                            _ = try stdout.write("\x1b[31m");
                            try stderr.print("wrong option\n\n", .{});
                            _ = try stdout.write("\x1b[0m");
                            try help();
                        },
                    }
                    needsArg = false;
                } else {
                    _ = try stdout.write("\x1b[1m\x1b[31m");
                    try stderr.print("wrong argument: {s}\n\n", .{value});
                    _ = try stdout.write("\x1b[m\x1b[0m");
                    try help();
                }
            },
        }
    }
    if (needsArg) {
        _ = try stdout.write("\x1b[31m");
        try stderr.print("missing option argument.\n", .{});
        _ = try stdout.write("\x1b[0m");
        try help();
    }
    // if nicName|filePath is undefined.
    if (@intFromPtr(nicName.ptr) == 0) {
        const nicList = try nic.getNICList();
        nicName = &nicList[1];
        _ = try stdout.write("\x1b[35m");
        try stdout.print("NIC:\t{s}\n", .{nicName});
        _ = try stdout.write("\x1b[0m");
    }
    if (@intFromPtr(filePath.ptr) == 0) {
        filePath = "dump.pcap";
        _ = try stdout.write("\x1b[35m");
        try stdout.print("captured results output to: {s}\n", .{filePath});
        _ = try stdout.write("\x1b[0m");
    }

    const cap = try Capture.init(nicName, promiscFlag, false);
    var pcap = try pcapFile.init(filePath);

    while (true) {
        if (os.read(cap.sock, &buf)) |size| {
            try pcap.save(&buf, @intCast(size));
        } else |err| {
            std.debug.print("{}", .{err});
        }
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
