#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bridge.h"

#define RESET    "\x1b[0m"
#define BOLD     "\x1b[1m"
#define DIM      "\x1b[2m"
#define PINK     "\x1b[38;5;213m"
#define PINK2    "\x1b[38;5;219m"
#define MAGENTA  "\x1b[38;5;201m"
#define LAVENDER "\x1b[38;5;183m"
#define CYAN     "\x1b[38;5;159m"
#define MINT     "\x1b[38;5;121m"
#define YELLOW   "\x1b[38;5;228m"
#define ORANGE   "\x1b[38;5;215m"
#define RED      "\x1b[38;5;210m"
#define RED2     "\x1b[38;5;196m"
#define GRAY     "\x1b[38;5;245m"
#define WHITE    "\x1b[38;5;255m"
#define TEAL     "\x1b[38;5;87m"
#define LIME     "\x1b[38;5;154m"
#define ROSE     "\x1b[38;5;204m"

static void print_banner(void) {
    printf("\x1b[2J\x1b[H");
    printf(PINK  "  ╔══════════════════════════════════════════════════════════════╗\n");
    printf(PINK  "  ║  " MAGENTA BOLD "✦  M A L C A T  v2.0  ✦  " PINK2 "Malware Analysis Toolkit" PINK "       \n" RESET);
    printf(PINK  "  ║  " LAVENDER "✧ Universal File Forensics ✧ Deep Heuristics ✧ Chi² Stats ✧" PINK " \n" RESET);
    printf(PINK  "  ║  " GRAY DIM "     ARM64 Asm • C • Zig  |  All File Types  |  uwu edition    " PINK "\n" RESET);
    printf(PINK  "  ╚══════════════════════════════════════════════════════════════╝\n" RESET);
}

static void print_menu(void) {
    printf(PINK2 "\n  ┌───────────────────────────────────────────┐\n");
    printf(PINK2 "  │  " CYAN BOLD "✿ MALCAT MENU ✿" PINK2 "                       \n" RESET);
    printf(PINK2 "  ├───────────────────────────────────────────┤\n");
    printf(PINK2 "  │  " MINT   "[1]" WHITE " Full Deep Analysis              " PINK2 "\n" RESET);
    printf(PINK2 "  │  " MINT   "[2]" WHITE " Signature Scan (18 patterns)    " PINK2 "\n" RESET);
    printf(PINK2 "  │  " MINT   "[3]" WHITE " Extract Strings                 " PINK2 "\n" RESET);
    printf(PINK2 "  │  " MINT   "[4]" WHITE " Entropy + Chi² Analysis         " PINK2 "\n" RESET);
    printf(PINK2 "  │  " TEAL   "[5]" WHITE " PE Header (Windows)             " PINK2 "\n" RESET);
    printf(PINK2 "  │  " TEAL   "[6]" WHITE " ELF Header (Linux/Unix)         " PINK2 "\n" RESET);
    printf(PINK2 "  │  " TEAL   "[7]" WHITE " File Type & Format Info         " PINK2 "\n" RESET);
    printf(PINK2 "  │  " LIME   "[8]" WHITE " Hex Dump (256 bytes)            " PINK2 "\n" RESET);
    printf(PINK2 "  │  " LIME   "[9]" WHITE " Checksums & Hashes              " PINK2 "\n" RESET);
    printf(PINK2 "  │  " YELLOW "[a]" WHITE " Suspicious Import Scan          " PINK2 "\n" RESET);
    printf(PINK2 "  │  " YELLOW "[b]" WHITE " Byte Frequency Distribution     " PINK2 "\n" RESET);
    printf(PINK2 "  │  " YELLOW "[c]" WHITE " XOR Key Brute-Force             " PINK2 "\n" RESET);
    printf(PINK2 "  │  " ORANGE "[f]" WHITE " Open New File                   " PINK2 "\n" RESET);
    printf(PINK2 "  │  " RED    "[q]" WHITE " Quit  (≧◡≦)                    " PINK2 "\n" RESET);
    printf(PINK2 "  └───────────────────────────────────────────┘\n" RESET);
}

static void divider(void) {
    printf(PINK "  ·───────────────────────────────────────────────────────────·\n" RESET);
}

static void section(const char *icon, const char *title) {
    printf(MAGENTA "\n  %s " BOLD WHITE "%s" RESET "\n", icon, title);
    divider();
}

static const char *threat_color(const char *lvl) {
    if (!strcmp(lvl, "CRITICAL")) return RED2 BOLD;
    if (!strcmp(lvl, "HIGH"))     return RED BOLD;
    if (!strcmp(lvl, "MEDIUM"))   return ORANGE BOLD;
    if (!strcmp(lvl, "LOW"))      return YELLOW;
    return MINT BOLD;
}

static void entropy_bar(double ent) {
    int p = (ent > 8.0) ? 40 : (int)(ent * 5.0);
    if (p > 40) p = 40;
    printf(LAVENDER "    Entropy Gauge         " RESET "[");
    for (int i = 0; i < 40; i++) {
        if (i < p) {
            if (p > 32) printf(RED2 "█");
            else if (p > 24) printf(ORANGE "█");
            else if (p > 16) printf(YELLOW "█");
            else printf(MINT "█");
        } else printf(GRAY "░");
    }
    printf(RESET "] " CYAN "%.5f" RESET " bits\n", ent);
}

static void chi2_bar(uint64_t chi2) {
    int p = (chi2 > 1000) ? 40 : (int)(chi2 * 40 / 1000);
    if (p > 40) p = 40;
    printf(LAVENDER "    Chi² Uniformity      " RESET "[");
    for (int i = 0; i < 40; i++) {
        if (i < p) printf(TEAL "▪");
        else printf(GRAY "·");
    }
    printf(RESET "] " CYAN "%llu" RESET, (unsigned long long)chi2);
    if (chi2 < 50)        printf(MINT "  ← very uniform (encrypted?)\n" RESET);
    else if (chi2 < 200)  printf(YELLOW "  ← moderate uniformity\n" RESET);
    else                  printf(ORANGE "  ← structured/compressible\n" RESET);
}

static void obf_bar(int64_t score) {
    int p = (score > 1000) ? 40 : (int)(score * 40 / 1000);
    if (p > 40) p = 40;
    printf(LAVENDER "    Obfuscation Score     " RESET "[");
    for (int i = 0; i < 40; i++) {
        if (i < p) {
            if (p > 30) printf(RED2 "▓");
            else if (p > 20) printf(RED "▓");
            else if (p > 10) printf(ORANGE "▓");
            else printf(YELLOW "▓");
        } else printf(GRAY "░");
    }
    printf(RESET "] " CYAN "%lld" RESET "/1000\n", (long long)score);
}

static void format_size(size_t sz) {
    if      (sz >= 1024*1024*1024) printf("%.2f GB", (double)sz/(1024.0*1024.0*1024.0));
    else if (sz >= 1024*1024)      printf("%.2f MB", (double)sz/(1024.0*1024.0));
    else if (sz >= 1024)           printf("%.2f KB", (double)sz/1024.0);
    else                           printf("%zu B", sz);
    printf(" (%zu bytes)", sz);
}

static void hex_dump(const uint8_t *data, size_t size) {
    size_t lim = size > 256 ? 256 : size;
    for (size_t i = 0; i < lim; i += 16) {
        printf(CYAN "    %08zX" RESET "  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i+j < lim) {
                uint8_t b = data[i+j];
                if      (b == 0x00)             printf(GRAY  "%02X " RESET, b);
                else if (b >= 0x20 && b <= 0x7E) printf(MINT  "%02X " RESET, b);
                else                             printf(ORANGE "%02X " RESET, b);
            } else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i+j < lim; j++) {
            uint8_t b = data[i+j];
            if (b >= 0x20 && b <= 0x7E) printf(WHITE "%c" RESET, b);
            else printf(GRAY "·" RESET);
        }
        printf("|\n");
    }
}

static void do_full(FileContext *ctx) {
    section("✿", "FULL DEEP ANALYSIS");
    printf(LAVENDER "    Path                  " WHITE "%s\n" RESET, ctx->file_path);
    printf(LAVENDER "    File Type             " CYAN  "%s\n" RESET, ctx->file_type);
    printf(LAVENDER "    MIME                  " GRAY  "%s\n" RESET, ctx->mime_type);
    printf(LAVENDER "    Size                  " WHITE);
    format_size(ctx->size);
    printf(RESET "\n");
    if (ctx->arch[0])
        printf(LAVENDER "    Architecture          " PINK2 "%s\n" RESET, ctx->arch);

    DeepAnalysis *da = &ctx->deep;

    entropy_bar(da->entropy);
    obf_bar(da->obf_score);
    chi2_bar(da->chi2);

    printf(LAVENDER "    Unique Bytes          " CYAN  "%llu" GRAY " / 256 distinct values\n" RESET,
           (unsigned long long)da->unique_bytes);
    printf(LAVENDER "    Null Bytes            " CYAN  "%llu" GRAY " (%.1f%%)\n" RESET,
           (unsigned long long)da->null_count,
           ctx->size ? (double)da->null_count*100.0/ctx->size : 0.0);
    printf(LAVENDER "    Printable Bytes       " CYAN  "%llu" GRAY " (%.1f%%)\n" RESET,
           (unsigned long long)da->printable_count,
           ctx->size ? (double)da->printable_count*100.0/ctx->size : 0.0);
    printf(LAVENDER "    Longest Null Run      " CYAN  "%llu bytes\n" RESET,
           (unsigned long long)da->longest_null_run);

    if (da->nop_sled_offset >= 0)
        printf(LAVENDER "    NOP Sled Detected     " RED "YES at 0x%llX\n" RESET,
               (unsigned long long)da->nop_sled_offset);
    else
        printf(LAVENDER "    NOP Sled              " MINT "None detected\n" RESET);

    printf(LAVENDER "    High-Entropy Blocks   " CYAN "%llu" GRAY " block(s) > 200 unique bytes/4KB\n" RESET,
           (unsigned long long)da->high_entropy_blocks);

    if (ctx->packer_hint[0])
        printf(LAVENDER "    Packer Hint           " ORANGE "%s\n" RESET, ctx->packer_hint);

    const char *tc = threat_color(ctx->threat_level);
    printf(LAVENDER "    Threat Level          " "%s%s\n" RESET, tc, ctx->threat_level);
    printf(LAVENDER "    Composite Score       " CYAN "%d\n" RESET, ctx->suspicious_score);

    static SigMatch matches[32];
    int nsigs = bridge_scan_signatures(ctx, matches, 32);
    if (nsigs > 0) {
        section("⚠", "SIGNATURE MATCHES");
        for (int i = 0; i < nsigs; i++) {
            printf(RED "    [!] " WHITE "%-48s" GRAY " @ 0x%llX" CYAN " ×%zu\n" RESET,
                   matches[i].name,
                   (unsigned long long)matches[i].offset,
                   matches[i].count);
        }
    } else {
        printf(MINT "\n    ✓ No known malware signatures detected (◕‿◕)\n" RESET);
    }
}

static void do_sig_scan(FileContext *ctx) {
    section("⚠", "SIGNATURE SCAN (18 pattern database)");
    static SigMatch matches[32];
    int nsigs = bridge_scan_signatures(ctx, matches, 32);
    if (nsigs > 0) {
        for (int i = 0; i < nsigs; i++) {
            printf(LAVENDER "    Sev: " CYAN "%3d%%" WHITE " │ " RED "%-48s\n" RESET,
                   matches[i].severity, matches[i].name);
            printf(GRAY "           @ Offset 0x%010llX │ %zu occurrence(s)\n" RESET,
                   (unsigned long long)matches[i].offset, matches[i].count);
        }
        printf(ORANGE "\n    Found %d match(es) ⚠ (⊙_⊙)\n" RESET, nsigs);
    } else {
        printf(MINT "\n    ✓ All clear! No signatures matched (⁀ᗢ⁀)\n" RESET);
    }
}

static void do_strings(FileContext *ctx) {
    section("❋", "EXTRACTED STRINGS (min 6 chars)");
    char *out = calloc(131072, 1);
    if (!out) { printf(RED "    ✗ Memory error\n" RESET); return; }
    int count = bridge_extract_strings(ctx->data, ctx->size, out, 131072, 6);
    if (count > 0) {
        int shown = 0;
        char *line = strtok(out, "\n");
        while (line && shown < 60) {
            printf(GRAY "    %s\n" RESET, line);
            line = strtok(NULL, "\n");
            shown++;
        }
        if (count > 60)
            printf(GRAY "    ... %d more strings omitted ...\n" RESET, count - 60);
        printf(LAVENDER "\n    Total: " CYAN "%d" LAVENDER " strings extracted\n" RESET, count);
    } else {
        printf(GRAY "    No printable strings found (very encrypted?)\n" RESET);
    }
    free(out);
}

static void do_entropy(FileContext *ctx) {
    section("♦", "ENTROPY + CHI² ANALYSIS");
    DeepAnalysis *da = &ctx->deep;
    entropy_bar(da->entropy);
    chi2_bar(da->chi2);
    printf("\n");

    if (da->entropy > 7.8)
        printf(RED "    ⚠ EXTREME entropy (>7.8). Almost certainly encrypted/packed.\n"
               ORANGE "      Recommended: run unpacker or dynamic analysis.\n" RESET);
    else if (da->entropy > 7.2)
        printf(ORANGE "    ⚠ Very high entropy. Likely compressed or encrypted section.\n" RESET);
    else if (da->entropy > 6.5)
        printf(YELLOW "    ~ High entropy. Possible crypto constants or compressed data.\n" RESET);
    else if (da->entropy > 4.5)
        printf(MINT   "    ✓ Moderate entropy. Typical executable/binary range.\n" RESET);
    else
        printf(MINT   "    ✓ Low entropy. Likely plain data or sparse binary.\n" RESET);

    printf("\n");
    printf(LAVENDER "    Chi² Score: " CYAN "%llu\n" RESET, (unsigned long long)da->chi2);
    if (da->chi2 < 50)
        printf(RED   "    ⚠ Chi² < 50: extremely uniform → AES/ChaCha stream cipher suspected\n" RESET);
    else if (da->chi2 < 200)
        printf(ORANGE "    ~ Chi² 50-200: moderately uniform → compressed or XOR'd data\n" RESET);
    else
        printf(MINT   "    ✓ Chi² > 200: non-uniform distribution → normal executable data\n" RESET);
}

static void do_pe(FileContext *ctx) {
    section("✦", "PE HEADER ANALYSIS");
    if (!ctx->is_pe) { printf(RED "    ✗ Not a PE file.\n" RESET); return; }
    printf(LAVENDER "    Machine               " WHITE "0x%04X  →  " PINK2 "%s\n" RESET,
           ctx->pe.machine, ctx->arch);
    printf(LAVENDER "    Timestamp             " CYAN  "0x%08X\n" RESET, ctx->pe.timestamp);

    if (ctx->pe.timestamp > 0) {
        time_t ts = (time_t)ctx->pe.timestamp;
        char tbuf[64];
        struct tm *tm_ = gmtime(&ts);
        if (tm_) {
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S UTC", tm_);
            printf(LAVENDER "    Compile Time          " GRAY "%s\n" RESET, tbuf);
        }
    }

    printf(LAVENDER "    Bitness               " CYAN  "%u-bit\n" RESET, ctx->pe.bitness);
    printf(LAVENDER "    Opt Header Size       " WHITE "%u bytes\n" RESET, ctx->pe.opt_header_size);
    printf(LAVENDER "    Characteristics       " WHITE "0x%04X\n" RESET, ctx->pe.characteristics);
    printf(LAVENDER "    Subsystem             " WHITE "%u", ctx->pe.subsystem);
    switch (ctx->pe.subsystem) {
        case 1:  printf(GRAY " (Native)\n"); break;
        case 2:  printf(GRAY " (Windows GUI)\n"); break;
        case 3:  printf(GRAY " (Windows CUI)\n"); break;
        case 5:  printf(GRAY " (OS/2 CUI)\n"); break;
        case 7:  printf(GRAY " (POSIX)\n"); break;
        case 9:  printf(GRAY " (Windows CE)\n"); break;
        case 10: printf(GRAY " (EFI Application)\n"); break;
        default: printf(GRAY " (Unknown)\n");
    }
    printf(RESET);
    printf(LAVENDER "\n    Flags:\n" RESET);
    uint32_t c = ctx->pe.characteristics;
    if (c & 0x0002) printf(MINT   "      ✓ Executable Image\n" RESET);
    if (c & 0x2000) printf(CYAN   "      ✓ DLL\n" RESET);
    if (c & 0x0020) printf(YELLOW "      ✓ Large Address Aware\n" RESET);
    if (c & 0x0200) printf(GRAY   "      · Stripped of relocs\n" RESET);
    if (c & 0x1000) printf(ORANGE "      ⚠ System file\n" RESET);
}

static void do_elf(FileContext *ctx) {
    section("✦", "ELF HEADER ANALYSIS");
    if (!ctx->is_elf) { printf(RED "    ✗ Not an ELF file.\n" RESET); return; }

    const char *cls  = ctx->elf.ei_class == 1 ? "ELF32" : ctx->elf.ei_class == 2 ? "ELF64" : "?";
    const char *end_ = ctx->elf.ei_data  == 1 ? "Little Endian (LE)" : "Big Endian (BE)";
    const char *etype;
    switch (ctx->elf.e_type) {
        case 1: etype = "ET_REL  (Relocatable)"; break;
        case 2: etype = "ET_EXEC (Executable)";  break;
        case 3: etype = "ET_DYN  (Shared Obj)";  break;
        case 4: etype = "ET_CORE (Core Dump)";   break;
        default: etype = "Unknown";
    }
    printf(LAVENDER "    Class                 " CYAN  "%s\n" RESET, cls);
    printf(LAVENDER "    Endianness            " WHITE "%s\n" RESET, end_);
    printf(LAVENDER "    Type                  " WHITE "%s\n" RESET, etype);
    printf(LAVENDER "    Machine               " WHITE "0x%04X  →  " PINK2 "%s\n" RESET,
           ctx->elf.e_machine, ctx->arch);
    printf(LAVENDER "    Section Count         " CYAN  "%u\n" RESET, ctx->elf.e_shnum);
}

static void do_file_info(FileContext *ctx) {
    section("♣", "FILE TYPE & FORMAT DETAILS");
    printf(LAVENDER "    Detected Type         " CYAN  "%s\n" RESET, ctx->file_type);
    printf(LAVENDER "    MIME Type             " GRAY  "%s\n" RESET, ctx->mime_type);
    printf(LAVENDER "    Size                  " WHITE); format_size(ctx->size); printf(RESET "\n");

    printf(LAVENDER "\n    Format Flags:         " RESET);
    if (ctx->is_pe)      printf(PINK  "[PE] " RESET);
    if (ctx->is_elf)     printf(CYAN  "[ELF] " RESET);
    if (ctx->is_macho)   printf(TEAL  "[Mach-O] " RESET);
    if (ctx->is_zip)     printf(YELLOW "[ZIP] " RESET);
    if (ctx->is_pdf)     printf(ORANGE "[PDF] " RESET);
    if (ctx->is_office)  printf(ORANGE "[OLE2] " RESET);
    if (ctx->is_script)  printf(LIME  "[SCRIPT] " RESET);
    if (ctx->is_image)   printf(MINT  "[IMAGE] " RESET);
    if (ctx->is_archive) printf(LAVENDER "[ARCHIVE] " RESET);
    if (ctx->is_unknown) printf(GRAY  "[UNKNOWN] " RESET);
    printf("\n");

    if (ctx->arch[0])
        printf(LAVENDER "    Architecture          " PINK2 "%s\n" RESET, ctx->arch);
    if (ctx->packer_hint[0])
        printf(LAVENDER "    Packer / Cryptor      " ORANGE "%s\n" RESET, ctx->packer_hint);

    DeepAnalysis *da = &ctx->deep;
    printf(LAVENDER "\n    Deep Stats:\n" RESET);
    printf(GRAY "      Entropy:         %.5f bits\n", da->entropy);
    printf(GRAY "      Chi²:            %llu\n", (unsigned long long)da->chi2);
    printf(GRAY "      Unique Bytes:    %llu / 256\n", (unsigned long long)da->unique_bytes);
    printf(GRAY "      Null Bytes:      %llu (%.1f%%)\n",
           (unsigned long long)da->null_count,
           ctx->size ? da->null_count*100.0/ctx->size : 0.0);
    printf(GRAY "      Printable:       %llu (%.1f%%)\n",
           (unsigned long long)da->printable_count,
           ctx->size ? da->printable_count*100.0/ctx->size : 0.0);
    printf(GRAY "      High-Ent Blocks: %llu\n", (unsigned long long)da->high_entropy_blocks);
    printf(GRAY "      Obf Score:       %lld / 1000\n" RESET, (long long)da->obf_score);
}

static void do_hex(FileContext *ctx) {
    section("♥", "HEX DUMP (first 256 bytes)");
    hex_dump(ctx->data, ctx->size);
    if (ctx->size > 256)
        printf(GRAY "\n    ... %zu bytes not shown ...\n" RESET, ctx->size - 256);
}

static void do_checksums(FileContext *ctx) {
    section("★", "CHECKSUMS & HASHES");
    printf(LAVENDER "    CRC-Sum32 (ASM)       " WHITE "0x%08X\n" RESET, ctx->checksum);
    printf(LAVENDER "    Adler-32 (ASM)        " WHITE "0x%08X\n" RESET, ctx->adler32);
    printf(LAVENDER "    XOR-Rotate Hash       " WHITE "0x%016llX\n" RESET,
           (unsigned long long)ctx->xor_hash);
    printf(LAVENDER "    File Size             " WHITE); format_size(ctx->size); printf(RESET "\n");
}

static void do_imports(FileContext *ctx) {
    section("⚡", "SUSPICIOUS IMPORT SCAN");
    if (!ctx->is_pe) {
        printf(ORANGE "    (Import scan is PE-specific — file is %s)\n" RESET, ctx->file_type);
        return;
    }
    char *buf = calloc(8192, 1);
    if (!buf) return;
    int found = bridge_scan_imports(ctx, buf, 8192);
    if (found > 0) {
        printf(RED "%s" RESET, buf);
        printf(ORANGE "\n    %d suspicious API(s) found ⚠\n" RESET, found);
    } else {
        printf(MINT "    ✓ No suspicious imports detected in string scan\n" RESET);
    }
    free(buf);
}

static void do_freq(FileContext *ctx) {
    section("♬", "BYTE FREQUENCY DISTRIBUTION");
    DeepAnalysis *da = &ctx->deep;
    uint32_t max_freq = 1;
    for (int i = 0; i < 256; i++)
        if (da->freq[i] > max_freq) max_freq = da->freq[i];

    printf(GRAY "    (showing top bytes by frequency)\n\n" RESET);

    uint32_t sorted[256];
    int idx[256];
    for (int i = 0; i < 256; i++) { sorted[i] = da->freq[i]; idx[i] = i; }
    for (int i = 0; i < 255; i++)
        for (int j = i+1; j < 256; j++)
            if (sorted[j] > sorted[i]) {
                uint32_t tmp = sorted[i]; sorted[i] = sorted[j]; sorted[j] = tmp;
                int ti = idx[i]; idx[i] = idx[j]; idx[j] = ti;
            }

    for (int i = 0; i < 20 && sorted[i] > 0; i++) {
        int bar = (int)(sorted[i] * 30 / max_freq);
        printf(CYAN "    0x%02X" GRAY " %c " RESET,
               idx[i],
               (idx[i] >= 0x20 && idx[i] <= 0x7E) ? idx[i] : '.');
        for (int b = 0; b < bar; b++) printf(LAVENDER "▪" RESET);
        printf(GRAY " %u\n" RESET, sorted[i]);
    }
    printf(GRAY "\n    Total unique bytes used: %llu / 256\n" RESET,
           (unsigned long long)da->unique_bytes);
}

static void do_xor(FileContext *ctx) {
    section("♮", "XOR KEY BRUTE-FORCE");
    DeepAnalysis *da = &ctx->deep;
    printf(LAVENDER "    Best XOR Key          " CYAN "0x%02X  ('%c')\n" RESET,
           da->xor_key,
           (da->xor_key >= 0x20 && da->xor_key <= 0x7E) ? da->xor_key : '.');
    printf(LAVENDER "    Printable Score       " CYAN "%llu bytes would be printable\n" RESET,
           (unsigned long long)da->xor_key_score);

    if (da->xor_key != 0 && da->xor_key_score > ctx->size / 2) {
        printf(ORANGE "\n    ⚠ Significant XOR obfuscation detected!\n");
        printf("      Key 0x%02X decodes %.1f%% of file to printable ASCII\n" RESET,
               da->xor_key,
               ctx->size ? (double)da->xor_key_score*100.0/ctx->size : 0.0);
        printf(GRAY "      First 64 bytes decoded:\n      ");
        for (size_t i = 0; i < 64 && i < ctx->size; i++) {
            uint8_t b = ctx->data[i] ^ da->xor_key;
            if (b >= 0x20 && b <= 0x7E) printf(MINT "%c" RESET, b);
            else printf(GRAY "." RESET);
        }
        printf("\n");
    } else if (da->xor_key == 0) {
        printf(MINT "\n    ✓ Key 0x00 = no XOR encoding (or key not found)\n" RESET);
    } else {
        printf(GRAY "\n    XOR score low — likely not XOR-encoded with single byte key\n" RESET);
    }
}

static int load_file(FileContext *ctx, const char *path) {
    int ret = bridge_load_file(ctx, path);
    if (ret != 0) {
        printf(RED "\n  ✗ Cannot load file (code %d)\n" RESET, ret);
        return 0;
    }
    bridge_classify_file(ctx);
    bridge_analyze_pe(ctx);
    bridge_analyze_elf(ctx);
    bridge_deep_analyze(ctx);
    bridge_detect_packer(ctx);
    bridge_assess_threat(ctx);
    printf(MINT "\n  ✓ Loaded: " WHITE "%s" MINT " (", path);
    format_size(ctx->size);
    printf(")\n" RESET);
    printf(CYAN "    Type: " WHITE "%s" RESET "\n", ctx->file_type);
    return 1;
}

static void wait_enter(void) {
    printf(GRAY "\n  ♡ Press Enter to continue..." RESET);
    fflush(stdout);
    char tmp[4];
    (void)fgets(tmp, sizeof(tmp), stdin);
}

int main(int argc, char *argv[]) {
    print_banner();

    FileContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    int loaded = 0;

    if (argc > 1) {
        loaded = load_file(&ctx, argv[1]);
    } else {
        printf(LAVENDER "  Usage: malcat <file>\n"
               "  Or enter a path below:\n\n" RESET);
        printf(PINK2 "  ♡ File path: " WHITE);
        fflush(stdout);
        char path[512];
        if (fgets(path, sizeof(path), stdin)) {
            size_t len = strlen(path);
            while (len > 0 && (path[len-1]=='\n'||path[len-1]=='\r')) path[--len]='\0';
            if (len > 0) loaded = load_file(&ctx, path);
        }
        printf(RESET);
    }

    while (1) {
        print_menu();
        if (loaded) {
            const char *tc = threat_color(ctx.threat_level);
            printf(GRAY "  File: " WHITE "%s" GRAY "  │  " CYAN "%s" GRAY "  │  Threat: %s%s\n" RESET,
                   ctx.file_type, ctx.arch[0] ? ctx.arch : "N/A", tc, ctx.threat_level);
        } else {
            printf(GRAY "  No file loaded  (｡•́︿•̀｡)\n" RESET);
        }

        printf(PINK "\n  ♡ Option: " WHITE);
        fflush(stdout);
        char line[8];
        if (!fgets(line, sizeof(line), stdin)) break;
        printf(RESET);
        char ch = line[0];

        if (!loaded && ch != 'f' && ch != 'q') {
            printf(ORANGE "\n  ⚠ No file loaded! Press [f] to open one.\n" RESET);
            continue;
        }

        switch (ch) {
            case '1': do_full(&ctx);     break;
            case '2': do_sig_scan(&ctx); break;
            case '3': do_strings(&ctx);  break;
            case '4': do_entropy(&ctx);  break;
            case '5': do_pe(&ctx);       break;
            case '6': do_elf(&ctx);      break;
            case '7': do_file_info(&ctx);break;
            case '8': do_hex(&ctx);      break;
            case '9': do_checksums(&ctx);break;
            case 'a': do_imports(&ctx);  break;
            case 'b': do_freq(&ctx);     break;
            case 'c': do_xor(&ctx);      break;
            case 'f': {
                if (loaded) bridge_free_file(&ctx);
                loaded = 0;
                printf(PINK2 "\n  ♡ File path: " WHITE);
                fflush(stdout);
                char path[512];
                if (fgets(path, sizeof(path), stdin)) {
                    size_t len = strlen(path);
                    while (len>0&&(path[len-1]=='\n'||path[len-1]=='\r')) path[--len]='\0';
                    if (len > 0) loaded = load_file(&ctx, path);
                }
                printf(RESET);
                continue;
            }
            case 'q': case 'Q':
                printf(PINK "\n  ♡ Goodbye! Stay safe~ (◕‿◕)♡\n\n" RESET);
                if (loaded) bridge_free_file(&ctx);
                return 0;
            default:
                printf(RED "\n  ✗ Invalid option\n" RESET);
        }
        wait_enter();
    }

    if (loaded) bridge_free_file(&ctx);
    return 0;
}

