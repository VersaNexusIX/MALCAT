#ifndef MALCAT_BRIDGE_H
#define MALCAT_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t machine;
    uint32_t timestamp;
    uint32_t opt_header_size;
    uint32_t characteristics;
    uint32_t subsystem;
    uint32_t bitness;
} PEInfo;

typedef struct {
    uint32_t ei_class;
    uint32_t ei_data;
    uint32_t e_type;
    uint32_t e_machine;
    uint32_t e_shnum;
} ELFInfo;

typedef struct {
    uint32_t magic;
} MachoInfo;

typedef struct {
    uint8_t sig1;
    uint8_t sig2;
} ZipInfo;

typedef struct {
    double   entropy;
    uint32_t freq[256];
    uint64_t chi2;
    uint64_t null_count;
    uint64_t printable_count;
    uint64_t unique_bytes;
    uint64_t longest_null_run;
    int64_t  nop_sled_offset;
    int64_t  sus_score;
    int64_t  obf_score;
    uint8_t  xor_key;
    uint64_t xor_key_score;
    int64_t  string_table_offset;
    uint64_t string_table_count;
    uint64_t high_entropy_blocks;
} DeepAnalysis;

typedef struct {
    char         file_path[512];
    uint8_t     *data;
    size_t       size;

    int          is_pe;
    int          is_elf;
    int          is_macho;
    int          is_zip;
    int          is_pdf;
    int          is_office;
    int          is_script;
    int          is_image;
    int          is_archive;
    int          is_unknown;

    PEInfo       pe;
    ELFInfo      elf;
    MachoInfo    macho;
    ZipInfo      zip;

    DeepAnalysis deep;

    uint32_t     checksum;
    uint32_t     adler32;
    uint64_t     xor_hash;

    char         file_type[128];
    char         mime_type[64];
    char         arch[48];
    char         threat_level[16];
    int          suspicious_score;
    char         packer_hint[64];
} FileContext;

typedef struct {
    const uint8_t *pattern;
    size_t         pattern_len;
    const char    *name;
    const char    *category;
    int            severity;
} Signature;

typedef struct {
    char    name[128];
    int64_t offset;
    size_t  count;
    int     severity;
} SigMatch;

extern int64_t  asm_compute_entropy(const uint8_t *data, size_t size, double *out);
extern void     asm_byte_frequency(const uint8_t *data, size_t size, uint32_t *freq);
extern int64_t  asm_scan_signature(const uint8_t *data, size_t dl, const uint8_t *sig, size_t sl);
extern int64_t  asm_find_all_occurrences(const uint8_t *d, size_t dl, const uint8_t *p, size_t pl, int64_t *out, size_t max);
extern int64_t  asm_parse_pe_magic(const uint8_t *data, PEInfo *out, size_t size);
extern int64_t  asm_parse_elf_magic(const uint8_t *data, size_t size, ELFInfo *out);
extern int64_t  asm_parse_macho_magic(const uint8_t *data, size_t size, uint32_t *out);
extern int64_t  asm_parse_zip_magic(const uint8_t *data, size_t size, uint8_t *out);
extern uint32_t asm_compute_checksum(const uint8_t *data, size_t size);
extern uint32_t asm_compute_adler32(const uint8_t *data, size_t size);
extern uint64_t asm_count_null_bytes(const uint8_t *data, size_t size);
extern uint64_t asm_count_printable(const uint8_t *data, size_t size);
extern int64_t  asm_detect_nop_sled(const uint8_t *data, size_t size, size_t min_run);
extern int64_t  asm_suspicious_score(const uint8_t *data, size_t size);
extern uint64_t asm_compute_chi2(const uint32_t *freq, size_t total);
extern int64_t  asm_find_pattern(const uint8_t *data, size_t dl, const uint8_t *pat, size_t pl);
extern uint64_t asm_xor_scan(const uint8_t *data, size_t size, uint8_t key);
extern void     asm_rot13(uint8_t *data, size_t size);
extern uint64_t asm_longest_run(const uint8_t *data, size_t size, uint8_t val);
extern uint64_t asm_detect_high_entropy_blocks(const uint8_t *d, size_t sz, size_t blk, int64_t *out, size_t max);
extern int64_t  asm_score_obfuscation(const uint8_t *data, size_t size);
extern uint64_t asm_detect_xor_key(const uint8_t *data, size_t size, uint8_t *out_key);
extern int64_t  asm_detect_string_table(const uint8_t *d, size_t sz, size_t min_len, uint64_t *cnt);

int    bridge_load_file(FileContext *ctx, const char *path);
void   bridge_free_file(FileContext *ctx);
void   bridge_classify_file(FileContext *ctx);
void   bridge_deep_analyze(FileContext *ctx);
void   bridge_analyze_pe(FileContext *ctx);
void   bridge_analyze_elf(FileContext *ctx);
void   bridge_assess_threat(FileContext *ctx);
int    bridge_scan_signatures(FileContext *ctx, SigMatch *matches, int max_matches);
int    bridge_extract_strings(const uint8_t *data, size_t size, char *out, size_t out_size, int min_len);
void   bridge_detect_packer(FileContext *ctx);
int    bridge_scan_imports(FileContext *ctx, char *out, size_t out_size);

#endif
