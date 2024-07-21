const std = @import("std");
const os = std.os;
const posix = std.posix;

pub const pcapFile = struct {
    const This = @This();
    file: std.fs.File,
    writer: std.io.Writer(std.fs.File, std.fs.File.WriteError, std.fs.File.write),
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    pub fn init(filePath: []const u8) !*This {
        var pcap = try gpa.allocator().create(This);
        errdefer pcap.deinit();

        pcap.file = try std.fs.cwd().createFile(filePath, .{});
        // pcap.file = try std.fs.createFileAbsolute(filePath, .{});
        pcap.writer = pcap.file.writer();

        // const ghdr = try pcapFileHeader.init(0xA1B2C3D4, 1);
        const ghdr = pcapFileHeader{};
        try pcap.writer.writeStruct(ghdr);

        return pcap;
    }

    fn deinit(pcap: *This) void {
        pcap.file.close();
        _ = gpa.deinit();
    }

    pub fn save(pcap: *This, buf: []u8, size: u32) !void {
        const phdr = try pcapPacketRecord.init(size, size);
        try pcap.writer.writeStruct(phdr.*);
        try pcap.writer.writeAll(buf[0..size]);
    }
};

pub const pcapFileHeader = extern struct {
    const This = @This();

    const PCAP_VERSION_MAJOR = 2;
    const PCAP_VERSION_MINOR = 4;

    const PcapError = error{
        IncorrectMagicNumber,
        OutOfMemory,
    };

    magic: u32 = 0xA1B2C3D4,
    version_major: u16 = PCAP_VERSION_MAJOR,
    version_minor: u16 = PCAP_VERSION_MINOR,
    thiszone: i32 = 0,
    sigfigs: u32 = 0,
    snaplen: u32 = 65535,
    linktype: u32 = 1,

    pub fn init(magic: usize, linktype: usize) PcapError!*This {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var pfhdr = try gpa.allocator().create(This);
        // if magic is 0xA1B2C3D4, timestamps in PacketRecord are in seconds and microseconds.
        // if magic is 0xA1B23C4D, timestamps in PacketRecord are in seconds and nanoseconds.
        if (magic != 0xA1B2C3D4 and magic != 0xA1B23C4D) {
            return PcapError.IncorrectMagicNumber;
        }
        pfhdr.magic = magic;
        pfhdr.linktype = linktype;

        return pfhdr;
    }
};

pub const pcapPacketRecord = extern struct {
    const This = @This();

    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    pub fn init(caplen: u32, len: u32) !*This {
        var pprcd = try gpa.allocator().create(This);
        errdefer pprcd.deinit();
        var tv: posix.timeval = .{
            .tv_sec = 1,
            .tv_usec = 1,
        };
        var tz: posix.timezone = undefined;
        _ = os.linux.gettimeofday(&tv, &tz);

        pprcd.ts_sec = @intCast(tv.tv_sec);
        pprcd.ts_usec = @intCast(tv.tv_usec);
        pprcd.incl_len = caplen;
        pprcd.orig_len = len;

        return pprcd;
    }

    fn deinit() void {
        _ = gpa.deinit();
    }
};
