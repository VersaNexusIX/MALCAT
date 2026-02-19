#include "bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

static const uint8_t MAG_MZ[]      = { 0x4D, 0x5A };
static const uint8_t MAG_ELF[]     = { 0x7F, 0x45, 0x4C, 0x46 };
static const uint8_t MAG_PDF[]     = { 0x25, 0x50, 0x44, 0x46 };
static const uint8_t MAG_ZIP[]     = { 0x50, 0x4B, 0x03, 0x04 };
static const uint8_t MAG_ZIP2[]    = { 0x50, 0x4B, 0x05, 0x06 };
static const uint8_t MAG_7Z[]      = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
static const uint8_t MAG_GZ[]      = { 0x1F, 0x8B };
static const uint8_t MAG_BZ2[]     = { 0x42, 0x5A, 0x68 };
static const uint8_t MAG_XZ[]      = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
static const uint8_t MAG_LZMA[]    = { 0x5D, 0x00, 0x00 };
static const uint8_t MAG_RAR[]     = { 0x52, 0x61, 0x72, 0x21 };
static const uint8_t MAG_PNG[]     = { 0x89, 0x50, 0x4E, 0x47 };
static const uint8_t MAG_JPG[]     = { 0xFF, 0xD8, 0xFF };
static const uint8_t MAG_GIF87[]   = { 0x47, 0x49, 0x46, 0x38, 0x37 };
static const uint8_t MAG_GIF89[]   = { 0x47, 0x49, 0x46, 0x38, 0x39 };
static const uint8_t MAG_WEBP[]    = { 0x52, 0x49, 0x46, 0x46 };
static const uint8_t MAG_BMP[]     = { 0x42, 0x4D };
static const uint8_t MAG_TIFF_LE[] = { 0x49, 0x49, 0x2A, 0x00 };
static const uint8_t MAG_TIFF_BE[] = { 0x4D, 0x4D, 0x00, 0x2A };
static const uint8_t MAG_DOC[]     = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
static const uint8_t MAG_DOCX[]    = { 0x50, 0x4B, 0x03, 0x04 };
static const uint8_t MAG_SHELL[]   = { 0x23, 0x21 };
static const uint8_t MAG_DEX[]     = { 0x64, 0x65, 0x78, 0x0A };
static const uint8_t MAG_CLASS[]   = { 0xCA, 0xFE, 0xBA, 0xBE };
static const uint8_t MAG_WASM[]    = { 0x00, 0x61, 0x73, 0x6D };
static const uint8_t MAG_SQLITE[]  = { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65 };
static const uint8_t MAG_EXR[]     = { 0x76, 0x2F, 0x31, 0x01 };
static const uint8_t MAG_FLAC[]    = { 0x66, 0x4C, 0x61, 0x43 };
static const uint8_t MAG_MP3[]     = { 0xFF, 0xFB };
static const uint8_t MAG_OGG[]     = { 0x4F, 0x67, 0x67, 0x53 };
static const uint8_t MAG_MP4[]     = { 0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70 };
static const uint8_t MAG_LNK[]     = { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 };
static const uint8_t MAG_SWF[]     = { 0x43, 0x57, 0x53 };
static const uint8_t MAG_SWF2[]    = { 0x46, 0x57, 0x53 };
static const uint8_t MAG_PCAP[]    = { 0xD4, 0xC3, 0xB2, 0xA1 };
static const uint8_t MAG_PCAPNG[]  = { 0x0A, 0x0D, 0x0D, 0x0A };
static const uint8_t MAG_UPX[]     = { 0x55, 0x50, 0x58, 0x21 };
static const uint8_t MAG_ASPACK[]  = { 0x60, 0xBE };
static const uint8_t MAG_NSPACK[]  = { 0x4E, 0x53, 0x50, 0x61, 0x63, 0x6B };
static const uint8_t MAG_MPRESS[]  = { 0x4D, 0x50, 0x52, 0x45, 0x53, 0x53 };

static const uint8_t SIG_METERP[]  = { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
static const uint8_t SIG_SHELLC[]  = { 0x31, 0xC0, 0x50, 0x68 };
static const uint8_t SIG_COBALT[]  = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xBE,0x00,0x00,0x00,0x00 };
static const uint8_t SIG_RANSOM[]  = { 0x2E, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74 };
static const uint8_t SIG_ROOTKIT[] = { 0x5C, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65 };
static const uint8_t SIG_MIMIKATZ[]= { 0x6D, 0x69, 0x6D, 0x69, 0x6B, 0x61, 0x74, 0x7A };
static const uint8_t SIG_NETSHT[]  = { 0x4E, 0x65, 0x74, 0x73, 0x68, 0x00 };
static const uint8_t SIG_CERTUTIL[]= { 0x63, 0x65, 0x72, 0x74, 0x75, 0x74, 0x69, 0x6C };
static const uint8_t SIG_POWSHELL[]= { 0x70, 0x6F, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6C, 0x6C };
static const uint8_t SIG_WSCRIPT[] = { 0x57, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74 };
static const uint8_t SIG_REGSVR[]  = { 0x72, 0x65, 0x67, 0x73, 0x76, 0x72, 0x33, 0x32 };
static const uint8_t SIG_CREATEP[] = { 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73 };
static const uint8_t SIG_WRITEPM[] = { 0x57, 0x72, 0x69, 0x74, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x4D };
static const uint8_t SIG_VIRT_ALLOC[]={ 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63 };
static const uint8_t SIG_LOADLIB[] = { 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79 };
static const uint8_t SIG_WINHTTPO[]= { 0x57, 0x69, 0x6E, 0x48, 0x74, 0x74, 0x70, 0x4F, 0x70, 0x65, 0x6E };
static const uint8_t SIG_EVAL_B64[]= { 0x65, 0x76, 0x61, 0x6C, 0x28, 0x62, 0x61, 0x73, 0x65, 0x36, 0x34 };
static const uint8_t SIG_OBFPS[]   = { 0x2D, 0x65, 0x6E, 0x63, 0x6F, 0x64, 0x65, 0x64, 0x63, 0x6F, 0x6D };

typedef struct {
    const uint8_t *pattern;
    size_t         len;
    const char    *name;
    const char    *category;
    int            severity;
} SigDef;

static const SigDef SIG_DB[] = {
    { SIG_METERP,    5,  "Metasploit Meterpreter",      "RAT/Backdoor",      95 },
    { SIG_SHELLC,    4,  "Generic Shellcode",            "Shellcode",         80 },
    { SIG_COBALT,    13, "CobaltStrike Beacon Pattern",  "C2/Backdoor",       92 },
    { SIG_RANSOM,    8,  "Ransomware .encrypt Marker",   "Ransomware",        85 },
    { SIG_ROOTKIT,   7,  "\\Device\\ Path (Rootkit)",   "Rootkit",           70 },
    { SIG_MIMIKATZ,  8,  "Mimikatz Credential Dumper",   "Credential Theft",  90 },
    { SIG_NETSHT,    6,  "Netsh Network Pivot",          "Lateral Movement",  60 },
    { SIG_CERTUTIL,  8,  "CertUtil Dropper Ref",         "Dropper/LOLBin",    75 },
    { SIG_POWSHELL,  10, "PowerShell LOLBin Ref",        "LOLBin/Dropper",    65 },
    { SIG_WSCRIPT,   7,  "WScript Script Host Ref",      "Script Host",       55 },
    { SIG_REGSVR,    8,  "Regsvr32 LOLBin Ref",          "LOLBin",            65 },
    { SIG_CREATEP,   13, "CreateProcess API",            "Process Injection",  50 },
    { SIG_WRITEPM,   13, "WriteProcessMemory API",       "Process Injection",  75 },
    { SIG_VIRT_ALLOC,12, "VirtualAlloc API",             "Shellcode/Inject",  60 },
    { SIG_LOADLIB,   11, "LoadLibrary API",              "DLL Injection",     45 },
    { SIG_WINHTTPO,  11, "WinHttpOpen C2 Comm",          "C2/Network",        70 },
    { SIG_EVAL_B64,  11, "eval(base64 Obfuscated Code",  "Script Obfuscation",78 },
    { SIG_OBFPS,     11, "PowerShell -encodedcommand",   "Script Obfuscation",72 },
};

static const int NUM_SIGS = (int)(sizeof(SIG_DB) / sizeof(SIG_DB[0]));

int bridge_load_file(FileContext *ctx, const char *path) {
    memset(ctx, 0, sizeof(FileContext));
    strncpy(ctx->file_path, path, 511);

    struct stat st;
    if (stat(path, &st) != 0) return -1;
    ctx->size = (size_t)st.st_size;
    if (ctx->size == 0) return -2;
    if (ctx->size > 512 * 1024 * 1024) return -3;

    ctx->data = (uint8_t *)malloc(ctx->size);
    if (!ctx->data) return -4;

    FILE *f = fopen(path, "rb");
    if (!f) { free(ctx->data); ctx->data = NULL; return -5; }

    size_t rd = fread(ctx->data, 1, ctx->size, f);
    fclose(f);
    if (rd != ctx->size) { free(ctx->data); ctx->data = NULL; return -6; }
    return 0;
}

void bridge_free_file(FileContext *ctx) {
    if (ctx && ctx->data) { free(ctx->data); ctx->data = NULL; }
}

static int match_magic(const uint8_t *data, size_t size, const uint8_t *mag, size_t mlen) {
    if (size < mlen) return 0;
    return memcmp(data, mag, mlen) == 0;
}

void bridge_classify_file(FileContext *ctx) {
    const uint8_t *d = ctx->data;
    size_t          s = ctx->size;
    if (!d || s < 2) { strncpy(ctx->file_type, "Empty/Unknown", 127); return; }

    ctx->is_pe = ctx->is_elf = ctx->is_macho = 0;
    ctx->is_zip = ctx->is_pdf = ctx->is_office = 0;
    ctx->is_script = ctx->is_image = ctx->is_archive = ctx->is_unknown = 0;

    if (match_magic(d, s, MAG_MZ, 2)) {
        strncpy(ctx->file_type, "PE (Windows Executable)", 127);
        strncpy(ctx->mime_type, "application/x-dosexec", 63);
        ctx->is_pe = 1;
    } else if (match_magic(d, s, MAG_ELF, 4)) {
        strncpy(ctx->file_type, "ELF (Linux/Unix Executable)", 127);
        strncpy(ctx->mime_type, "application/x-elf", 63);
        ctx->is_elf = 1;
    } else if (s >= 4 && (match_magic(d, s, (const uint8_t*)"\xCE\xFA\xED\xFE", 4) ||
                           match_magic(d, s, (const uint8_t*)"\xCF\xFA\xED\xFE", 4) ||
                           match_magic(d, s, (const uint8_t*)"\xFE\xED\xFA\xCE", 4) ||
                           match_magic(d, s, (const uint8_t*)"\xFE\xED\xFA\xCF", 4) ||
                           match_magic(d, s, (const uint8_t*)"\xCA\xFE\xBA\xBE", 4))) {
        strncpy(ctx->file_type, "Mach-O (macOS/iOS Executable)", 127);
        strncpy(ctx->mime_type, "application/x-mach-binary", 63);
        ctx->is_macho = 1;
    } else if (match_magic(d, s, MAG_PDF, 4)) {
        strncpy(ctx->file_type, "PDF Document", 127);
        strncpy(ctx->mime_type, "application/pdf", 63);
        ctx->is_pdf = 1;
    } else if (match_magic(d, s, MAG_DOC, 8)) {
        strncpy(ctx->file_type, "MS Office Document (OLE2/CFB)", 127);
        strncpy(ctx->mime_type, "application/msword", 63);
        ctx->is_office = 1;
    } else if (match_magic(d, s, MAG_CLASS, 4)) {
        strncpy(ctx->file_type, "Java Class File", 127);
        strncpy(ctx->mime_type, "application/java-vm", 63);
    } else if (match_magic(d, s, MAG_DEX, 4)) {
        strncpy(ctx->file_type, "Android DEX (Dalvik Executable)", 127);
        strncpy(ctx->mime_type, "application/vnd.android.dex", 63);
    } else if (match_magic(d, s, MAG_WASM, 4)) {
        strncpy(ctx->file_type, "WebAssembly Module", 127);
        strncpy(ctx->mime_type, "application/wasm", 63);
    } else if (match_magic(d, s, MAG_LNK, 8)) {
        strncpy(ctx->file_type, "Windows Shortcut (.lnk) — HIGH RISK", 127);
        strncpy(ctx->mime_type, "application/x-ms-shortcut", 63);
        ctx->suspicious_score += 30;
    } else if (match_magic(d, s, MAG_SWF, 3) || match_magic(d, s, MAG_SWF2, 3)) {
        strncpy(ctx->file_type, "Adobe Flash (SWF)", 127);
        strncpy(ctx->mime_type, "application/x-shockwave-flash", 63);
    } else if (match_magic(d, s, MAG_ZIP, 4) || match_magic(d, s, MAG_ZIP2, 4)) {
        strncpy(ctx->file_type, "ZIP Archive", 127);
        strncpy(ctx->mime_type, "application/zip", 63);
        ctx->is_zip = 1; ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_7Z, 6)) {
        strncpy(ctx->file_type, "7-Zip Archive", 127);
        strncpy(ctx->mime_type, "application/x-7z-compressed", 63);
        ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_GZ, 2)) {
        strncpy(ctx->file_type, "GZip Compressed", 127);
        strncpy(ctx->mime_type, "application/gzip", 63);
        ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_BZ2, 3)) {
        strncpy(ctx->file_type, "BZip2 Compressed", 127);
        strncpy(ctx->mime_type, "application/x-bzip2", 63);
        ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_XZ, 6)) {
        strncpy(ctx->file_type, "XZ Compressed", 127);
        strncpy(ctx->mime_type, "application/x-xz", 63);
        ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_RAR, 4)) {
        strncpy(ctx->file_type, "RAR Archive", 127);
        strncpy(ctx->mime_type, "application/x-rar-compressed", 63);
        ctx->is_archive = 1;
    } else if (match_magic(d, s, MAG_PNG, 4)) {
        strncpy(ctx->file_type, "PNG Image", 127);
        strncpy(ctx->mime_type, "image/png", 63);
        ctx->is_image = 1;
    } else if (match_magic(d, s, MAG_JPG, 3)) {
        strncpy(ctx->file_type, "JPEG Image", 127);
        strncpy(ctx->mime_type, "image/jpeg", 63);
        ctx->is_image = 1;
    } else if (match_magic(d, s, MAG_GIF87, 5) || match_magic(d, s, MAG_GIF89, 5)) {
        strncpy(ctx->file_type, "GIF Image", 127);
        strncpy(ctx->mime_type, "image/gif", 63);
        ctx->is_image = 1;
    } else if (match_magic(d, s, MAG_BMP, 2)) {
        strncpy(ctx->file_type, "BMP Image", 127);
        strncpy(ctx->mime_type, "image/bmp", 63);
        ctx->is_image = 1;
    } else if (match_magic(d, s, MAG_TIFF_LE, 4) || match_magic(d, s, MAG_TIFF_BE, 4)) {
        strncpy(ctx->file_type, "TIFF Image", 127);
        strncpy(ctx->mime_type, "image/tiff", 63);
        ctx->is_image = 1;
    } else if (match_magic(d, s, MAG_SQLITE, 6)) {
        strncpy(ctx->file_type, "SQLite Database", 127);
        strncpy(ctx->mime_type, "application/x-sqlite3", 63);
    } else if (match_magic(d, s, MAG_PCAP, 4)) {
        strncpy(ctx->file_type, "PCAP Network Capture", 127);
        strncpy(ctx->mime_type, "application/vnd.tcpdump.pcap", 63);
    } else if (match_magic(d, s, MAG_PCAPNG, 4)) {
        strncpy(ctx->file_type, "PCAPNG Network Capture", 127);
        strncpy(ctx->mime_type, "application/vnd.tcpdump.pcap", 63);
    } else if (match_magic(d, s, MAG_FLAC, 4)) {
        strncpy(ctx->file_type, "FLAC Audio", 127);
        strncpy(ctx->mime_type, "audio/flac", 63);
    } else if (match_magic(d, s, MAG_OGG, 4)) {
        strncpy(ctx->file_type, "OGG Audio/Video", 127);
        strncpy(ctx->mime_type, "audio/ogg", 63);
    } else if (match_magic(d, s, MAG_SHELL, 2)) {
        strncpy(ctx->file_type, "Shell Script / Shebang", 127);
        strncpy(ctx->mime_type, "text/x-shellscript", 63);
        ctx->is_script = 1;
    } else {
        int maybe_text = 1;
        size_t check = s < 512 ? s : 512;
        for (size_t i = 0; i < check; i++) {
            uint8_t c = d[i];
            if (c < 0x09 || (c > 0x0D && c < 0x20 && c != 0x1B)) {
                maybe_text = 0; break;
            }
        }
        if (maybe_text) {
            strncpy(ctx->file_type, "Plain Text / Script", 127);
            strncpy(ctx->mime_type, "text/plain", 63);
            ctx->is_script = 1;
        } else {
            strncpy(ctx->file_type, "Unknown Binary", 127);
            strncpy(ctx->mime_type, "application/octet-stream", 63);
            ctx->is_unknown = 1;
        }
    }
}

void bridge_analyze_pe(FileContext *ctx) {
    if (!ctx->is_pe || !ctx->data || ctx->size < 64) return;
    if (!asm_parse_pe_magic(ctx->data, &ctx->pe, ctx->size)) return;

    switch (ctx->pe.machine) {
        case 0x014C: strncpy(ctx->arch, "x86 (i386)", 47); break;
        case 0x8664: strncpy(ctx->arch, "x86-64 (AMD64)", 47); break;
        case 0xAA64: strncpy(ctx->arch, "ARM64 (AArch64)", 47); break;
        case 0x01C0: strncpy(ctx->arch, "ARM", 47); break;
        case 0x01C4: strncpy(ctx->arch, "ARM Thumb-2", 47); break;
        case 0x0200: strncpy(ctx->arch, "Intel Itanium (IA64)", 47); break;
        case 0x0166: strncpy(ctx->arch, "MIPS R3000 LE", 47); break;
        case 0x5032: strncpy(ctx->arch, "RISC-V 32-bit", 47); break;
        case 0x5064: strncpy(ctx->arch, "RISC-V 64-bit", 47); break;
        default:     snprintf(ctx->arch, 47, "Unknown (0x%04X)", ctx->pe.machine); break;
    }
}

void bridge_analyze_elf(FileContext *ctx) {
    if (!ctx->is_elf || !ctx->data || ctx->size < 16) return;
    if (!asm_parse_elf_magic(ctx->data, ctx->size, &ctx->elf)) return;

    switch (ctx->elf.e_machine) {
        case 0x003E: strncpy(ctx->arch, "x86-64 (AMD64)", 47); break;
        case 0x0003: strncpy(ctx->arch, "x86 (i386)", 47); break;
        case 0x00B7: strncpy(ctx->arch, "ARM64 (AArch64)", 47); break;
        case 0x0028: strncpy(ctx->arch, "ARM", 47); break;
        case 0x0002: strncpy(ctx->arch, "SPARC", 47); break;
        case 0x0008: strncpy(ctx->arch, "MIPS", 47); break;
        case 0x0015: strncpy(ctx->arch, "PowerPC", 47); break;
        case 0x0016: strncpy(ctx->arch, "PowerPC 64-bit", 47); break;
        case 0x0032: strncpy(ctx->arch, "Intel IA-64", 47); break;
        case 0x00F3: strncpy(ctx->arch, "RISC-V", 47); break;
        case 0x004E: strncpy(ctx->arch, "AMD x86-64 (old)", 47); break;
        default:     snprintf(ctx->arch, 47, "Unknown (0x%04X)", ctx->elf.e_machine); break;
    }
}

void bridge_deep_analyze(FileContext *ctx) {
    if (!ctx->data || !ctx->size) return;
    DeepAnalysis *da = &ctx->deep;

    asm_byte_frequency(ctx->data, ctx->size, da->freq);
    asm_compute_entropy(ctx->data, ctx->size, &da->entropy);

    da->null_count     = asm_count_null_bytes(ctx->data, ctx->size);
    da->printable_count= asm_count_printable(ctx->data, ctx->size);
    da->sus_score      = asm_suspicious_score(ctx->data, ctx->size);
    da->obf_score      = asm_score_obfuscation(ctx->data, ctx->size);
    da->chi2           = asm_compute_chi2(da->freq, ctx->size);
    da->nop_sled_offset= asm_detect_nop_sled(ctx->data, ctx->size, 8);
    da->longest_null_run = asm_longest_run(ctx->data, ctx->size, 0x00);
    da->xor_key_score  = asm_detect_xor_key(ctx->data, ctx->size, &da->xor_key);

    static int64_t heb_offsets[64];
    da->high_entropy_blocks = asm_detect_high_entropy_blocks(
        ctx->data, ctx->size, 4096, heb_offsets, 64);

    da->string_table_offset = asm_detect_string_table(
        ctx->data, ctx->size, 5, &da->string_table_count);

    da->unique_bytes = 0;
    for (int i = 0; i < 256; i++)
        if (da->freq[i]) da->unique_bytes++;

    ctx->checksum = asm_compute_checksum(ctx->data, ctx->size);
    ctx->adler32  = asm_compute_adler32(ctx->data, ctx->size);

    ctx->xor_hash = 0x1337DEADBEEFULL;
    for (size_t i = 0; i < ctx->size; i++) {
        ctx->xor_hash ^= (uint64_t)ctx->data[i] << (i % 56);
        ctx->xor_hash  = (ctx->xor_hash << 13) | (ctx->xor_hash >> 51);
        ctx->xor_hash += (uint64_t)ctx->data[i] * 0x9E3779B97F4A7BBULL;
    }
}

void bridge_detect_packer(FileContext *ctx) {
    if (!ctx->data) return;
    ctx->packer_hint[0] = '\0';

    if (asm_scan_signature(ctx->data, ctx->size, MAG_UPX, 4) >= 0) {
        strncpy(ctx->packer_hint, "UPX (Ultimate Packer)", 63); return;
    }
    if (asm_scan_signature(ctx->data, ctx->size, MAG_ASPACK, 2) >= 0) {
        strncpy(ctx->packer_hint, "ASPack", 63); return;
    }
    if (asm_scan_signature(ctx->data, ctx->size, MAG_NSPACK, 6) >= 0) {
        strncpy(ctx->packer_hint, "NSPack", 63); return;
    }
    if (asm_scan_signature(ctx->data, ctx->size, MAG_MPRESS, 6) >= 0) {
        strncpy(ctx->packer_hint, "MPRESS", 63); return;
    }
    if (ctx->deep.entropy > 7.4) {
        strncpy(ctx->packer_hint, "Unknown (high entropy — packed/encrypted)", 63);
    }
}

void bridge_assess_threat(FileContext *ctx) {
    int score = ctx->suspicious_score;
    DeepAnalysis *da = &ctx->deep;

    if (da->entropy > 7.5) score += 35;
    else if (da->entropy > 7.0) score += 20;
    else if (da->entropy > 6.5) score += 10;

    if (da->obf_score > 700) score += 30;
    else if (da->obf_score > 400) score += 15;

    if (da->nop_sled_offset >= 0) score += 25;

    if (da->chi2 < 100 && ctx->size > 1024) score += 15;

    if (da->unique_bytes > 240) score += 10;

    if (ctx->packer_hint[0]) score += 20;

    if (ctx->is_pe || ctx->is_elf || ctx->is_macho) {
        if (da->sus_score > 500) score += 20;
    }

    if (score >= 90)       strncpy(ctx->threat_level, "CRITICAL", 15);
    else if (score >= 60)  strncpy(ctx->threat_level, "HIGH", 15);
    else if (score >= 30)  strncpy(ctx->threat_level, "MEDIUM", 15);
    else if (score >= 10)  strncpy(ctx->threat_level, "LOW", 15);
    else                   strncpy(ctx->threat_level, "CLEAN", 15);

    ctx->suspicious_score = score;
    ctx->deep.entropy = da->entropy;
}

int bridge_scan_signatures(FileContext *ctx, SigMatch *matches, int max_matches) {
    if (!ctx->data || !matches || max_matches <= 0) return 0;
    int found = 0;

    for (int i = 0; i < NUM_SIGS && found < max_matches; i++) {
        int64_t pos = asm_scan_signature(
            ctx->data, (int64_t)ctx->size,
            SIG_DB[i].pattern, (int64_t)SIG_DB[i].len);
        if (pos >= 0) {
            snprintf(matches[found].name, 127, "%s", SIG_DB[i].name);
            matches[found].offset   = pos;
            matches[found].severity = SIG_DB[i].severity;
            snprintf(matches[found].name, 127, "%s [%s]",
                     SIG_DB[i].name, SIG_DB[i].category);

            static int64_t all_offsets[32];
            int64_t cnt = asm_find_all_occurrences(
                ctx->data, ctx->size,
                SIG_DB[i].pattern, SIG_DB[i].len,
                all_offsets, 32);
            matches[found].count = (cnt > 0) ? (size_t)cnt : 1;
            found++;
            ctx->suspicious_score += SIG_DB[i].severity;
        }
    }
    return found;
}

int bridge_extract_strings(const uint8_t *data, size_t size,
                           char *out, size_t out_size, int min_len) {
    if (!data || !out) return 0;
    int count = 0;
    size_t out_off = 0;
    int run = 0;
    size_t start = 0;

    for (size_t i = 0; i <= size; i++) {
        uint8_t c = (i < size) ? data[i] : 0;
        int printable = (c >= 0x20 && c <= 0x7E) ||
                        c == 0x09 || c == 0x0A || c == 0x0D;
        if (printable) {
            if (run == 0) start = i;
            run++;
        } else {
            if (run >= min_len) {
                size_t copy_len = run > 255 ? 255 : (size_t)run;
                if (out_off + 16 + copy_len + 2 < out_size) {
                    int wrote = snprintf(out + out_off,
                                         out_size - out_off,
                                         "0x%08zX: ", start);
                    out_off += (size_t)wrote;
                    memcpy(out + out_off, data + start, copy_len);
                    out_off += copy_len;
                    out[out_off++] = '\n';
                    count++;
                }
            }
            run = 0;
        }
    }
    if (out_off < out_size) out[out_off] = '\0';
    return count;
}

int bridge_scan_imports(FileContext *ctx, char *out, size_t out_size) {
    if (!ctx->data || !out) return 0;
    if (!ctx->is_pe) return 0;

    static const uint8_t *DANGEROUS_IMPORTS[] = {
        (const uint8_t*)"VirtualAllocEx",
        (const uint8_t*)"WriteProcessMemory",
        (const uint8_t*)"CreateRemoteThread",
        (const uint8_t*)"OpenProcess",
        (const uint8_t*)"NtUnmapViewOfSection",
        (const uint8_t*)"SetWindowsHookEx",
        (const uint8_t*)"GetAsyncKeyState",
        (const uint8_t*)"InternetOpenUrl",
        (const uint8_t*)"URLDownloadToFile",
        (const uint8_t*)"ShellExecute",
        (const uint8_t*)"WinExec",
        (const uint8_t*)"IsDebuggerPresent",
        (const uint8_t*)"CheckRemoteDebuggerPresent",
        (const uint8_t*)"NtQueryInformationProcess",
        (const uint8_t*)"RegSetValueEx",
        (const uint8_t*)"CryptEncrypt",
        (const uint8_t*)"CryptDecrypt",
    };

    int count = 0;
    size_t off = 0;
    int nimports = (int)(sizeof(DANGEROUS_IMPORTS)/sizeof(DANGEROUS_IMPORTS[0]));

    for (int i = 0; i < nimports; i++) {
        size_t slen = strlen((const char*)DANGEROUS_IMPORTS[i]);
        int64_t pos = asm_scan_signature(
            ctx->data, ctx->size,
            DANGEROUS_IMPORTS[i], slen);
        if (pos >= 0) {
            int wrote = snprintf(out + off, out_size - off,
                "  ⚠ %-32s @ 0x%llX\n",
                (const char*)DANGEROUS_IMPORTS[i],
                (unsigned long long)pos);
            if (wrote > 0) off += (size_t)wrote;
            count++;
        }
    }
    return count;
}
