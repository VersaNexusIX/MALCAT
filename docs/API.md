# API.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

Reference for all public C types and functions in `src/bridge.h` and
`src/bridge.c`. Useful if you want to embed MALCAT's analysis pipeline
into another C tool.

---

## Structs

### `PEInfo`

```c
typedef struct {
    uint32_t machine;          // e.g. 0x8664 = x86-64, 0xAA64 = ARM64
    uint32_t timestamp;        // Unix epoch from PE header
    uint32_t opt_header_size;
    uint32_t characteristics;
    uint32_t subsystem;        // 2=GUI, 3=CUI, 10=EFI app, etc.
    uint32_t bitness;          // 32 or 64
} PEInfo;
```

### `ELFInfo`

```c
typedef struct {
    uint32_t ei_class;    // 1=ELF32, 2=ELF64
    uint32_t ei_data;     // 1=LE, 2=BE
    uint32_t e_type;      // 1=REL, 2=EXEC, 3=DYN, 4=CORE
    uint32_t e_machine;   // e.g. 0x3E=x86-64, 0xB7=AArch64
    uint32_t e_shnum;     // section header count
} ELFInfo;
```

### `DeepAnalysis`

```c
typedef struct {
    double   entropy;              // Shannon entropy, 0.0–8.0 bits
    uint32_t freq[256];            // byte frequency table
    uint64_t chi2;                 // chi-squared uniformity statistic
    uint64_t null_count;           // count of 0x00 bytes
    uint64_t printable_count;      // count of bytes in [0x20, 0x7E]
    uint64_t unique_bytes;         // distinct byte values present
    uint64_t longest_null_run;     // longest consecutive run of 0x00
    int64_t  nop_sled_offset;      // offset of NOP sled, or -1
    int64_t  sus_score;            // raw suspicious opcode score
    int64_t  obf_score;            // obfuscation score 0–1000
    uint8_t  xor_key;              // best single-byte XOR key found
    uint64_t xor_key_score;        // printable bytes with that key
    int64_t  string_table_offset;  // offset of string cluster, or -1
    uint64_t string_table_count;   // string count in that cluster
    uint64_t high_entropy_blocks;  // 4 KB blocks with >250 distinct bytes
} DeepAnalysis;
```

### `FileContext`

```c
typedef struct {
    char         file_path[512];
    uint8_t     *data;             // heap buffer, freed by bridge_free_file
    size_t       size;

    int          is_pe, is_elf, is_macho;
    int          is_zip, is_pdf, is_office;
    int          is_script, is_image, is_archive, is_unknown;

    PEInfo       pe;
    ELFInfo      elf;
    MachoInfo    macho;
    ZipInfo      zip;

    DeepAnalysis deep;

    uint32_t     checksum;         // additive byte sum
    uint32_t     adler32;
    uint64_t     xor_hash;         // internal rotate-XOR hash

    char         file_type[128];   // human-readable type string
    char         mime_type[64];
    char         arch[48];         // architecture string (PE/ELF only)
    char         threat_level[16]; // CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    int          suspicious_score; // composite heuristic score
    char         packer_hint[64];  // detected packer name, or empty
} FileContext;
```

### `SigMatch`

```c
typedef struct {
    char    name[128];   // signature name and category
    int64_t offset;      // first match offset in file
    size_t  count;       // total occurrences
    int     severity;    // 0–100
} SigMatch;
```

---

## Functions

### `bridge_load_file`

```c
int bridge_load_file(FileContext *ctx, const char *path);
```

Zeroes `ctx`, then reads the file at `path` into `ctx->data`.

Return values:

| Code | Meaning |
|---|---|
| 0 | success |
| -1 | `stat()` failed |
| -2 | file is empty |
| -3 | file > 512 MB |
| -4 | `malloc` failed |
| -5 | `fopen` failed |
| -6 | `fread` short read |

---

### `bridge_free_file`

```c
void bridge_free_file(FileContext *ctx);
```

Frees `ctx->data` and sets the pointer to NULL. Safe to call multiple times.

---

### `bridge_classify_file`

```c
void bridge_classify_file(FileContext *ctx);
```

Sets `ctx->file_type`, `ctx->mime_type`, and all `is_*` flags based on
magic bytes. Must be called after `bridge_load_file`.

---

### `bridge_analyze_pe` / `bridge_analyze_elf`

```c
void bridge_analyze_pe(FileContext *ctx);
void bridge_analyze_elf(FileContext *ctx);
```

Fills `ctx->pe` / `ctx->elf` and `ctx->arch`. No-op if the corresponding
`is_pe` / `is_elf` flag is 0.

---

### `bridge_deep_analyze`

```c
void bridge_deep_analyze(FileContext *ctx);
```

Runs all assembly analysis functions and fills `ctx->deep`, `ctx->checksum`,
`ctx->adler32`, and `ctx->xor_hash`. The slowest call for large files
(mainly due to `asm_detect_xor_key`).

---

### `bridge_detect_packer`

```c
void bridge_detect_packer(FileContext *ctx);
```

Scans for UPX, ASPack, NSPack, MPRESS byte signatures. Sets `ctx->packer_hint`.
Also sets a fallback hint if entropy > 7.4. Call after `bridge_deep_analyze`.

---

### `bridge_assess_threat`

```c
void bridge_assess_threat(FileContext *ctx);
```

Combines all signals into `ctx->suspicious_score` and `ctx->threat_level`.

Thresholds (approximate — score accumulates across analysis steps):

| Level | Score |
|---|---|
| CLEAN | < 10 |
| LOW | 10–29 |
| MEDIUM | 30–59 |
| HIGH | 60–89 |
| CRITICAL | ≥ 90 |

---

### `bridge_scan_signatures`

```c
int bridge_scan_signatures(FileContext *ctx, SigMatch *matches, int max_matches);
```

Scans against the 18-pattern database. Returns number of matches found.
Also adds each match's severity to `ctx->suspicious_score`.

---

### `bridge_extract_strings`

```c
int bridge_extract_strings(const uint8_t *data, size_t size,
                            char *out, size_t out_size, int min_len);
```

Extracts printable ASCII strings of at least `min_len` characters.
Output format per string: `"0x00001234: content\n"`.
Returns string count. Stops writing when `out` is full.

---

### `bridge_scan_imports`

```c
int bridge_scan_imports(FileContext *ctx, char *out, size_t out_size);
```

String-scans for 17 dangerous Windows API names in the file buffer.
Only useful for PE files; returns 0 for other types.
This is a string search, not an IAT parse — false positives are expected
when strings happen to appear in data sections.

---

## Minimal Usage Example

```c
#include "bridge.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    FileContext ctx;
    if (bridge_load_file(&ctx, argv[1]) != 0) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    bridge_classify_file(&ctx);
    bridge_analyze_pe(&ctx);
    bridge_analyze_elf(&ctx);
    bridge_deep_analyze(&ctx);
    bridge_detect_packer(&ctx);
    bridge_assess_threat(&ctx);

    printf("type:    %s\n", ctx.file_type);
    printf("entropy: %.4f bits\n", ctx.deep.entropy);
    printf("threat:  %s (score %d)\n", ctx.threat_level, ctx.suspicious_score);

    SigMatch matches[32];
    int n = bridge_scan_signatures(&ctx, matches, 32);
    for (int i = 0; i < n; i++)
        printf("  sig: %s @ 0x%llx\n", matches[i].name,
               (unsigned long long)matches[i].offset);

    bridge_free_file(&ctx);
    return 0;
}
```

Build:
```bash
gcc -Isrc src/engine_stub.c src/bridge.c your_tool.c -lm -o your_tool
```
