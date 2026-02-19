const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const fs = std.fs;
const io = std.io;

const c = @cImport({
    @cInclude("bridge.h");
});

const Color = struct {
    const reset   = "\x1b[0m";
    const bold    = "\x1b[1m";
    const pink    = "\x1b[38;5;213m";
    const pink2   = "\x1b[38;5;219m";
    const magenta = "\x1b[38;5;201m";
    const lavender= "\x1b[38;5;183m";
    const cyan    = "\x1b[38;5;159m";
    const mint    = "\x1b[38;5;121m";
    const yellow  = "\x1b[38;5;228m";
    const orange  = "\x1b[38;5;215m";
    const red     = "\x1b[38;5;210m";
    const red2    = "\x1b[38;5;196m";
    const gray    = "\x1b[38;5;245m";
    const white   = "\x1b[38;5;255m";
    const bg_dark = "\x1b[48;5;235m";
    const dim     = "\x1b[2m";
};

const BANNER =
    Color.pink  ++ "  ╔══════════════════════════════════════════════════════════╗\n" ++
    Color.pink  ++ "  ║  " ++ Color.magenta ++ Color.bold ++ "✦  M A L C A T  ✦  " ++
    Color.pink2 ++ "Malware Analysis Toolkit" ++ Color.pink ++ "         \n" ++
    Color.pink  ++ "  ║  " ++ Color.lavender ++ "✧ PE/ELF Analysis ✧ Signature Scanner ✧ File Forensics ✧" ++ Color.pink ++ " \n" ++
    Color.pink  ++ "  ║  " ++ Color.gray ++ Color.dim ++ "        ARM64 • C • Zig  |  v1.0.0  |  uwu edition          " ++ Color.pink ++ "\n" ++
    Color.pink  ++ "  ╚══════════════════════════════════════════════════════════╝\n" ++
    Color.reset;

const MENU =
    Color.pink2 ++ "\n  ┌─────────────────────────────────────────┐\n" ++
    Color.pink2 ++ "  │  " ++ Color.cyan ++ Color.bold ++ "✿ MALCAT MENU ✿" ++ Color.pink2 ++ "                     \n" ++
    Color.pink2 ++ "  ├─────────────────────────────────────────┤\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[1]" ++ Color.white ++ " Analyze File (Full)            " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[2]" ++ Color.white ++ " Signature Scan                 " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[3]" ++ Color.white ++ " Extract Strings                " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[4]" ++ Color.white ++ " Entropy Analysis               " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[5]" ++ Color.white ++ " PE Header Info                 " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[6]" ++ Color.white ++ " ELF Header Info                " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[7]" ++ Color.white ++ " Hex Dump (First 256 bytes)     " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.mint    ++ "[8]" ++ Color.white ++ " Checksum & File Hash           " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.orange  ++ "[9]" ++ Color.white ++ " Open New File                  " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  │  " ++ Color.red     ++ "[0]" ++ Color.white ++ " Exit  (≧◡≦)                   " ++ Color.pink2 ++ "\n" ++
    Color.pink2 ++ "  └─────────────────────────────────────────┘\n" ++
    Color.reset;

const stdout_file = std.io.getStdOut();
const stderr_file = std.io.getStdErr();
var bw = std.io.bufferedWriter(stdout_file.writer());
const stdout = bw.writer();

fn flush() void {
    bw.flush() catch {};
}

fn print(comptime fmt: []const u8, args: anytype) void {
    stdout.print(fmt, args) catch {};
}

fn println(comptime fmt: []const u8, args: anytype) void {
    stdout.print(fmt ++ "\n", args) catch {};
}

fn printRaw(s: []const u8) void {
    stdout.writeAll(s) catch {};
}

fn divider() void {
    printRaw(Color.pink ++ "  ·─────────────────────────────────────────────────────────·\n" ++ Color.reset);
}

fn sectionHeader(icon: []const u8, title: []const u8) void {
    print(Color.magenta ++ "\n  {s} " ++ Color.bold ++ Color.white ++ "{s}" ++ Color.reset ++ "\n", .{icon, title});
    divider();
}

fn labelVal(label: []const u8, comptime fmt: []const u8, args: anytype) void {
    print(Color.lavender ++ "    {s:<28}" ++ Color.white ++ fmt ++ Color.reset ++ "\n", .{label} ++ args);
}

fn threatColor(level: []const u8) []const u8 {
    if (std.mem.eql(u8, level, "CRITICAL")) return Color.red2 ++ Color.bold;
    if (std.mem.eql(u8, level, "HIGH"))     return Color.red ++ Color.bold;
    if (std.mem.eql(u8, level, "MEDIUM"))   return Color.orange ++ Color.bold;
    if (std.mem.eql(u8, level, "LOW"))      return Color.yellow;
    return Color.mint ++ Color.bold;
}

fn entropyBar(entropy: f64) void {
    const pct: usize = if (entropy > 8.0) 40 else @intFromFloat(entropy * 5.0);
    const filled = @min(pct, 40);
    print(Color.lavender ++ "    Entropy Gauge         " ++ Color.reset ++ "[", .{});
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        if (i < filled) {
            if (filled > 32) printRaw(Color.red ++ "█")
            else if (filled > 24) printRaw(Color.orange ++ "█")
            else if (filled > 16) printRaw(Color.yellow ++ "█")
            else printRaw(Color.mint ++ "█");
        } else {
            printRaw(Color.gray ++ "░");
        }
    }
    print(Color.reset ++ "]  " ++ Color.cyan ++ "{d:.4}" ++ Color.reset ++ " bits\n", .{entropy});
}

fn suspiciousBar(score: i32) void {
    const pct: usize = if (score > 100) 40 else @intFromFloat(@as(f64, @floatFromInt(score)) * 0.4);
    const filled = @min(pct, 40);
    print(Color.lavender ++ "    Suspicion Meter       " ++ Color.reset ++ "[", .{});
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        if (i < filled) {
            if (filled > 30) printRaw(Color.red2 ++ "▓")
            else if (filled > 20) printRaw(Color.red ++ "▓")
            else if (filled > 10) printRaw(Color.orange ++ "▓")
            else printRaw(Color.yellow ++ "▓");
        } else {
            printRaw(Color.gray ++ "░");
        }
    }
    print(Color.reset ++ "]  " ++ Color.cyan ++ "{d}pts" ++ Color.reset ++ "\n", .{score});
}

fn hexDump(data: [*c]const u8, size: usize) void {
    const limit = if (size > 256) 256 else size;
    var i: usize = 0;
    while (i < limit) : (i += 16) {
        print(Color.cyan ++ "    {X:0>8}" ++ Color.reset ++ "  ", .{i});
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            if (i + j < limit) {
                const byte = data[i + j];
                if (byte == 0x00) printRaw(Color.gray)
                else if (byte >= 0x20 and byte <= 0x7E) printRaw(Color.mint)
                else printRaw(Color.orange);
                print("{X:0>2} " ++ Color.reset, .{byte});
            } else {
                printRaw("   ");
            }
            if (j == 7) printRaw(" ");
        }
        printRaw(" |");
        j = 0;
        while (j < 16) : (j += 1) {
            if (i + j < limit) {
                const byte = data[i + j];
                if (byte >= 0x20 and byte <= 0x7E) {
                    printRaw(Color.white);
                    print("{c}", .{byte});
                } else {
                    printRaw(Color.gray ++ "·");
                }
                printRaw(Color.reset);
            }
        }
        printRaw("|\n");
    }
}

fn formatSize(size: usize) void {
    if (size >= 1024 * 1024) {
        print("{d:.2} MB ({d} bytes)", .{@as(f64, @floatFromInt(size)) / (1024.0 * 1024.0), size});
    } else if (size >= 1024) {
        print("{d:.2} KB ({d} bytes)", .{@as(f64, @floatFromInt(size)) / 1024.0, size});
    } else {
        print("{d} bytes", .{size});
    }
}

fn doFullAnalysis(ctx: *c.FileContext) void {
    sectionHeader("✿", "FULL FILE ANALYSIS");

    const file_type = std.mem.sliceTo(&ctx.file_type, 0);
    const arch_str  = std.mem.sliceTo(&ctx.arch, 0);
    const threat    = std.mem.sliceTo(&ctx.threat_level, 0);
    const path      = std.mem.sliceTo(&ctx.file_path, 0);

    print(Color.lavender ++ "    File Path             " ++ Color.white ++ "{s}" ++ Color.reset ++ "\n", .{path});
    print(Color.lavender ++ "    File Type             " ++ Color.cyan ++ "{s}" ++ Color.reset ++ "\n", .{file_type});
    print(Color.lavender ++ "    File Size             " ++ Color.white, .{});
    formatSize(ctx.size);
    printRaw(Color.reset ++ "\n");
    if (arch_str.len > 0) {
        print(Color.lavender ++ "    Architecture          " ++ Color.pink2 ++ "{s}" ++ Color.reset ++ "\n", .{arch_str});
    }

    entropyBar(ctx.entropy);
    suspiciousBar(ctx.suspicious_score);

    const tc = threatColor(threat);
    print(Color.lavender ++ "    Threat Level          " ++ "{s}{s}" ++ Color.reset ++ "\n", .{tc, threat});

    var sigs: [8192]u8 = undefined;
    const nsigs = c.bridge_scan_signatures(ctx, &sigs, 8192);
    if (nsigs > 0) {
        sectionHeader("⚠", "SIGNATURE MATCHES");
        print(Color.red ++ "{s}" ++ Color.reset, .{std.mem.sliceTo(&sigs, 0)});
    } else {
        print(Color.mint ++ "\n    ✓ No known malware signatures detected (◕‿◕)\n" ++ Color.reset, .{});
    }

    flush();
}

fn doPESections(ctx: *c.FileContext) void {
    sectionHeader("✦", "PE HEADER ANALYSIS");
    if (ctx.is_pe == 0) {
        printRaw(Color.red ++ "    ✗ Not a PE file!\n" ++ Color.reset);
        flush();
        return;
    }
    const machines = [_][2][]const u8{
        .{"0x014C", "x86 (i386)"},
        .{"0x8664", "x86-64 (AMD64)"},
        .{"0xAA64", "ARM64 (AArch64)"},
        .{"0x01C0", "ARM"},
    };
    _ = machines;

    labelVal("Machine Type:", "0x{X:0>4}", .{ctx.pe.machine});
    labelVal("Timestamp:", "0x{X:0>8}", .{ctx.pe.timestamp});
    labelVal("Opt Header Size:", "{d} bytes", .{ctx.pe.opt_header_size});
    labelVal("Characteristics:", "0x{X:0>4}", .{ctx.pe.characteristics});
    labelVal("Subsystem:", "{d}", .{ctx.pe.subsystem});
    labelVal("Architecture:", "{s}", .{std.mem.sliceTo(&ctx.arch, 0)});

    const chars = ctx.pe.characteristics;
    printRaw(Color.lavender ++ "\n    PE Flags:\n" ++ Color.reset);
    if (chars & 0x0002 != 0) printRaw(Color.mint ++ "      ✓ Executable\n" ++ Color.reset);
    if (chars & 0x2000 != 0) printRaw(Color.cyan ++ "      ✓ DLL\n" ++ Color.reset);
    if (chars & 0x0100 != 0) printRaw(Color.yellow ++ "      ✓ 32-bit\n" ++ Color.reset);
    if (chars & 0x0020 != 0) printRaw(Color.orange ++ "      ⚠ Large Address Aware\n" ++ Color.reset);

    flush();
}

fn doELFSections(ctx: *c.FileContext) void {
    sectionHeader("✦", "ELF HEADER ANALYSIS");
    if (ctx.is_elf == 0) {
        printRaw(Color.red ++ "    ✗ Not an ELF file!\n" ++ Color.reset);
        flush();
        return;
    }

    const cls = if (ctx.elf.ei_class == 1) "ELF32" else if (ctx.elf.ei_class == 2) "ELF64" else "Unknown";
    const end = if (ctx.elf.ei_data == 1) "Little Endian" else if (ctx.elf.ei_data == 2) "Big Endian" else "Unknown";
    const etype = switch (ctx.elf.e_type) {
        1 => "Relocatable",
        2 => "Executable",
        3 => "Shared Object",
        4 => "Core Dump",
        else => "Unknown",
    };

    labelVal("Class:", "{s}", .{cls});
    labelVal("Endianness:", "{s}", .{end});
    labelVal("Type:", "{s}", .{etype});
    labelVal("Machine:", "0x{X:0>4}", .{ctx.elf.e_machine});
    labelVal("Architecture:", "{s}", .{std.mem.sliceTo(&ctx.arch, 0)});
    labelVal("Sections:", "{d}", .{ctx.elf.e_shnum});
    flush();
}

fn doSigScan(ctx: *c.FileContext) void {
    sectionHeader("⚠", "SIGNATURE SCAN");
    var sigs: [16384]u8 = undefined;
    const nsigs = c.bridge_scan_signatures(ctx, &sigs, 16384);
    if (nsigs > 0) {
        print(Color.red ++ "{s}" ++ Color.reset, .{std.mem.sliceTo(&sigs, 0)});
        print(Color.orange ++ "\n    Found {d} signature match(es) (⊙_⊙)\n" ++ Color.reset, .{nsigs});
    } else {
        printRaw(Color.mint ++ "\n    ✓ All clear! No evil signatures found (⁀ᗢ⁀)\n" ++ Color.reset);
    }
    flush();
}

fn doStrings(ctx: *c.FileContext) void {
    sectionHeader("❋", "EXTRACTED STRINGS (min 6 chars)");
    const buf_size = 65536;
    const buf = std.heap.page_allocator.alloc(u8, buf_size) catch {
        printRaw(Color.red ++ "    ✗ Memory allocation failed\n" ++ Color.reset);
        flush();
        return;
    };
    defer std.heap.page_allocator.free(buf);

    const count = c.bridge_extract_strings(ctx.data, ctx.size, buf.ptr, buf_size, 6);
    if (count > 0) {
        var lines = std.mem.splitScalar(u8, buf[0..std.mem.indexOf(u8, buf, "\x00") orelse buf.len], '\n');
        var shown: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (shown >= 50) {
                print(Color.gray ++ "    ... and {d} more strings (truncated)\n" ++ Color.reset, .{count - 50});
                break;
            }
            print(Color.gray ++ "    {s}\n" ++ Color.reset, .{line});
            shown += 1;
        }
        print(Color.lavender ++ "\n    Total: " ++ Color.cyan ++ "{d}" ++ Color.lavender ++ " strings extracted\n" ++ Color.reset, .{count});
    } else {
        printRaw(Color.gray ++ "    No printable strings found\n" ++ Color.reset);
    }
    flush();
}

fn doEntropy(ctx: *c.FileContext) void {
    sectionHeader("♦", "ENTROPY ANALYSIS");
    entropyBar(ctx.entropy);
    print("\n", .{});
    if (ctx.entropy > 7.5) {
        printRaw(Color.red ++ "    ⚠ VERY HIGH entropy! Likely packed/encrypted/obfuscated!\n" ++ Color.reset);
        printRaw(Color.orange ++ "      Possible packer: UPX, ASPack, Themida, or custom crypto\n" ++ Color.reset);
    } else if (ctx.entropy > 6.8) {
        printRaw(Color.orange ++ "    ⚠ High entropy. May contain compressed data or crypto\n" ++ Color.reset);
    } else if (ctx.entropy > 5.0) {
        printRaw(Color.yellow ++ "    ~ Moderate entropy. Normal for most executables\n" ++ Color.reset);
    } else {
        printRaw(Color.mint ++ "    ✓ Low entropy. Likely plaintext or simple binary (˵ᵕ̴᷄ ˶̫ ᵕ̴᷅˵)\n" ++ Color.reset);
    }
    flush();
}

fn doHexDump(ctx: *c.FileContext) void {
    sectionHeader("♥", "HEX DUMP (First 256 bytes)");
    hexDump(ctx.data, ctx.size);
    flush();
}

fn doChecksum(ctx: *c.FileContext) void {
    sectionHeader("★", "CHECKSUMS & HASHES");
    const asm_cksum = c.asm_compute_checksum(ctx.data, ctx.size);
    labelVal("ASM Checksum (sum32):", "0x{X:0>8}", .{asm_cksum});
    labelVal("File Size:", "{d} bytes", .{ctx.size});

    var simple_hash: u64 = 0x1337BABE;
    var i: usize = 0;
    while (i < ctx.size) : (i += 1) {
        simple_hash ^= @as(u64, ctx.data[i]) << @intCast(i % 56);
        simple_hash = (simple_hash << 13) | (simple_hash >> 51);
        simple_hash +%= @as(u64, ctx.data[i]) *% 0x6B;
    }
    labelVal("XOR-Rotate Hash:", "0x{X:0>16}", .{simple_hash});
    flush();
}

fn prompt(comptime msg: []const u8) ![]u8 {
    printRaw(msg);
    flush();
    const stdin = std.io.getStdIn().reader();
    var buf: [512]u8 = undefined;
    const line = try stdin.readUntilDelimiterOrEof(&buf, '\n') orelse return error.EOF;
    return std.heap.page_allocator.dupe(u8, std.mem.trimRight(u8, line, "\r\n"));
}

fn loadFile(path: []const u8, ctx: *c.FileContext) bool {
    const cpath = std.heap.page_allocator.dupeZ(u8, path) catch return false;
    defer std.heap.page_allocator.free(cpath);

    const ret = c.bridge_load_file(ctx, cpath.ptr);
    if (ret != 0) {
        print(Color.red ++ "\n  ✗ Failed to load file (error {d})\n" ++ Color.reset, .{ret});
        flush();
        return false;
    }

    c.bridge_classify_file(ctx);
    _ = c.bridge_analyze_pe(ctx);
    _ = c.bridge_analyze_elf(ctx);
    _ = c.asm_compute_entropy(ctx.data, ctx.size, &ctx.entropy);
    ctx.checksum = c.asm_compute_checksum(ctx.data, ctx.size);
    c.bridge_assess_threat(ctx);

    print(Color.mint ++ "\n  ✓ Loaded: " ++ Color.white ++ "{s}" ++ Color.mint ++ " ({d} bytes)\n" ++ Color.reset, .{path, ctx.size});
    flush();
    return true;
}

fn getChoice() u8 {
    printRaw(Color.pink ++ "\n  ♡ Choose an option: " ++ Color.white);
    flush();
    const stdin = std.io.getStdIn().reader();
    var buf: [8]u8 = undefined;
    const line = stdin.readUntilDelimiterOrEof(&buf, '\n') catch return 255;
    printRaw(Color.reset);
    if (line == null or line.?.len == 0) return 255;
    return line.?[0];
}

pub fn main() !void {
    printRaw("\x1b[2J\x1b[H");
    printRaw(BANNER);
    printRaw("\n");

    var ctx: c.FileContext = undefined;
    var file_loaded = false;

    var args = std.process.args();
    _ = args.next();
    const initial_file = args.next();

    if (initial_file) |fpath| {
        file_loaded = loadFile(fpath, &ctx);
    } else {
        printRaw(Color.lavender ++ "  Usage: malcat <file>  or enter a path below\n\n" ++ Color.reset);
        const path = prompt(Color.pink2 ++ "  ♡ File path to analyze: " ++ Color.white) catch {
            printRaw(Color.red ++ "  ✗ Input error\n" ++ Color.reset);
            return;
        };
        defer std.heap.page_allocator.free(path);
        if (path.len > 0) {
            file_loaded = loadFile(path, &ctx);
        }
    }

    while (true) {
        printRaw(MENU);

        if (file_loaded) {
            const file_type = std.mem.sliceTo(&ctx.file_type, 0);
            const threat = std.mem.sliceTo(&ctx.threat_level, 0);
            const tc = threatColor(threat);
            print(Color.gray ++ "  Current: " ++ Color.white ++ "{s}" ++ Color.gray ++
                "  |  Threat: " ++ "{s}{s}" ++ Color.reset ++ "\n", .{file_type, tc, threat});
        } else {
            printRaw(Color.gray ++ "  No file loaded  (｡•́︿•̀｡)\n" ++ Color.reset);
        }

        const choice = getChoice();

        if (!file_loaded and choice != '9' and choice != '0') {
            printRaw(Color.orange ++ "\n  ⚠ Please load a file first! Press [9] to open a file.\n" ++ Color.reset);
            continue;
        }

        switch (choice) {
            '1' => doFullAnalysis(&ctx),
            '2' => doSigScan(&ctx),
            '3' => doStrings(&ctx),
            '4' => doEntropy(&ctx),
            '5' => doPESections(&ctx),
            '6' => doELFSections(&ctx),
            '7' => doHexDump(&ctx),
            '8' => doChecksum(&ctx),
            '9' => {
                if (file_loaded) c.bridge_free_file(&ctx);
                file_loaded = false;
                const path = prompt(Color.pink2 ++ "\n  ♡ New file path: " ++ Color.white) catch continue;
                defer std.heap.page_allocator.free(path);
                if (path.len > 0) file_loaded = loadFile(path, &ctx);
            },
            '0' => {
                printRaw(Color.pink ++ "\n  ♡ Goodbye! Stay safe out there (◕‿◕)♡\n\n" ++ Color.reset);
                flush();
                if (file_loaded) c.bridge_free_file(&ctx);
                return;
            },
            else => {
                printRaw(Color.red ++ "\n  ✗ Invalid option! Try again~\n" ++ Color.reset);
            },
        }
        printRaw(Color.gray ++ "\n  Press Enter to continue..." ++ Color.reset);
        flush();
        const stdin = std.io.getStdIn().reader();
        var tmp: [4]u8 = undefined;
        _ = stdin.readUntilDelimiterOrEof(&tmp, '\n') catch {};
    }
}

