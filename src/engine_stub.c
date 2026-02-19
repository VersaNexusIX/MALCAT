#include "bridge.h"
#include <string.h>
#include <math.h>
#include <stdint.h>

int64_t asm_compute_entropy(const uint8_t *data, size_t size, double *out) {
    if (!data || !size || !out) return -1;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    double sz = (double)size;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            double p = (double)freq[i] / sz;
            entropy -= p * log2(p);
        }
    }
    *out = entropy;
    return 0;
}

void asm_byte_frequency(const uint8_t *data, size_t size, uint32_t *freq) {
    if (!data || !freq) return;
    memset(freq, 0, 256 * sizeof(uint32_t));
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
}

int64_t asm_scan_signature(const uint8_t *data, size_t dl, const uint8_t *sig, size_t sl) {
    if (!data || !sig || sl > dl) return -1;
    for (size_t i = 0; i <= dl - sl; i++)
        if (memcmp(data + i, sig, sl) == 0) return (int64_t)i;
    return -1;
}

int64_t asm_find_all_occurrences(const uint8_t *d, size_t dl, const uint8_t *p, size_t pl, int64_t *out, size_t max) {
    if (!d || !p || pl > dl) return 0;
    int64_t cnt = 0;
    for (size_t i = 0; i <= dl - pl && (size_t)cnt < max; i++)
        if (memcmp(d + i, p, pl) == 0) out[cnt++] = (int64_t)i++;
    return cnt;
}

int64_t asm_parse_pe_magic(const uint8_t *data, PEInfo *out, size_t size) {
    if (!data || !out || size < 64) return 0;
    if (data[0] != 0x4D || data[1] != 0x5A) return 0;
    uint32_t pe_off = *(const uint32_t *)(data + 0x3C);
    if (pe_off + 24 >= size) return 0;
    const uint8_t *pe = data + pe_off;
    if (*(const uint32_t *)pe != 0x00004550) return 0;
    out->machine         = *(const uint16_t *)(pe + 4);
    out->timestamp       = *(const uint32_t *)(pe + 8);
    out->opt_header_size = *(const uint16_t *)(pe + 20);
    out->characteristics = *(const uint16_t *)(pe + 22);
    uint16_t magic = *(const uint16_t *)(pe + 24);
    if (magic == 0x10B) {
        out->subsystem = *(const uint16_t *)(pe + 0x44 + 24 - 4);
        out->bitness = 32;
    } else {
        out->subsystem = *(const uint16_t *)(pe + 0x44 + 24 - 4);
        out->bitness = 64;
    }
    return 1;
}

int64_t asm_parse_elf_magic(const uint8_t *data, size_t size, ELFInfo *out) {
    if (!data || !out || size < 64) return 0;
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') return 0;
    out->ei_class  = data[4];
    out->ei_data   = data[5];
    out->e_type    = *(const uint16_t *)(data + 16);
    out->e_machine = *(const uint16_t *)(data + 18);
    out->e_shnum   = (data[4] == 2) ? *(const uint16_t *)(data + 60) : *(const uint16_t *)(data + 48);
    return 1;
}

int64_t asm_parse_macho_magic(const uint8_t *data, size_t size, uint32_t *out) {
    if (!data || size < 4) return 0;
    uint32_t m = *(const uint32_t *)data;
    if (m == 0xFEEDFACE || m == 0xCEFAEDFE ||
        m == 0xFEEDFACF || m == 0xCFFAEDFE ||
        m == 0xCAFEBABE) {
        if (out) *out = m;
        return 1;
    }
    return 0;
}

int64_t asm_parse_zip_magic(const uint8_t *data, size_t size, uint8_t *out) {
    if (!data || size < 4) return 0;
    if (data[0] != 0x50 || data[1] != 0x4B) return 0;
    if (out) { out[0] = data[2]; out[1] = data[3]; }
    return 1;
}

uint32_t asm_compute_checksum(const uint8_t *data, size_t size) {
    uint32_t s = 0;
    for (size_t i = 0; i < size; i++) s += data[i];
    return s;
}

uint32_t asm_compute_adler32(const uint8_t *data, size_t size) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < size; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

uint64_t asm_count_null_bytes(const uint8_t *data, size_t size) {
    uint64_t n = 0;
    for (size_t i = 0; i < size; i++) if (!data[i]) n++;
    return n;
}

uint64_t asm_count_printable(const uint8_t *data, size_t size) {
    uint64_t n = 0;
    for (size_t i = 0; i < size; i++)
        if (data[i] >= 0x20 && data[i] <= 0x7E) n++;
    return n;
}

int64_t asm_detect_nop_sled(const uint8_t *data, size_t size, size_t min_run) {
    size_t run = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0x90 || data[i] == 0x00) {
            run++;
            if (run >= min_run) return (int64_t)(i - run + 1);
        } else run = 0;
    }
    return -1;
}

int64_t asm_suspicious_score(const uint8_t *data, size_t size) {
    int64_t s = 0;
    for (size_t i = 0; i < size; i++) {
        if      (data[i] == 0x90) s += 4;
        else if (data[i] == 0xCC) s += 12;
        else if (data[i] == 0xEB) s += 3;
        else if (data[i] == 0xE8) s += 2;
    }
    return s;
}

uint64_t asm_compute_chi2(const uint32_t *freq, size_t total) {
    if (!freq || !total) return 0;
    uint64_t exp = total / 256;
    if (!exp) return 0;
    uint64_t chi2 = 0;
    for (int i = 0; i < 256; i++) {
        int64_t d = (int64_t)freq[i] - (int64_t)exp;
        chi2 += (uint64_t)(d * d) / exp;
    }
    return chi2;
}

int64_t asm_find_pattern(const uint8_t *data, size_t dl, const uint8_t *pat, size_t pl) {
    if (!data || !pat || pl > dl) return -1;
    for (size_t i = 0; i <= dl - pl; i++)
        if (memcmp(data + i, pat, pl) == 0) return (int64_t)i;
    return -1;
}

uint64_t asm_xor_scan(const uint8_t *data, size_t size, uint8_t key) {
    uint64_t s = 0;
    for (size_t i = 0; i < size; i++) s += data[i] ^ key;
    return s;
}

void asm_rot13(uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        uint8_t c = data[i];
        if      (c >= 'A' && c <= 'Z') data[i] = ((c - 'A' + 13) % 26) + 'A';
        else if (c >= 'a' && c <= 'z') data[i] = ((c - 'a' + 13) % 26) + 'a';
    }
}

uint64_t asm_longest_run(const uint8_t *data, size_t size, uint8_t val) {
    uint64_t best = 0, cur = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == val) { if (++cur > best) best = cur; }
        else cur = 0;
    }
    return best;
}

uint64_t asm_detect_high_entropy_blocks(const uint8_t *d, size_t sz, size_t blk,
                                         int64_t *out, size_t max) {
    uint64_t cnt = 0;
    for (size_t i = 0; i < sz && cnt < max; i += blk) {
        size_t end = i + blk < sz ? i + blk : sz;
        uint8_t seen[256] = {0};
        int unique = 0;
        for (size_t j = i; j < end; j++)
            if (!seen[d[j]]) { seen[d[j]] = 1; unique++; }
        if (unique > 200) { out[cnt++] = (int64_t)i; }
    }
    return cnt;
}

int64_t asm_score_obfuscation(const uint8_t *data, size_t size) {
    if (!data || !size) return 0;
    uint64_t nulls = 0, print = 0, sops = 0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        uint8_t b = data[i];
        freq[b]++;
        if (!b) nulls++;
        if (b >= 0x20 && b <= 0x7E) print++;
        if (b == 0x90 || b == 0xCC || b == 0xEB) sops++;
    }
    int64_t score = 0;
    int64_t nr = (int64_t)(nulls * 256 / size);
    if (nr < 200) score += nr;
    int64_t pr = (int64_t)(print * 256 / size);
    int64_t inv = 200 - pr; if (inv < 0) inv = 0; if (inv > 200) inv = 200;
    score += inv;
    int64_t sp = (int64_t)(sops * 16); if (sp > 300) sp = 300;
    score += sp;
    int uniq = 0; for (int i = 0; i < 256; i++) if (freq[i]) uniq++;
    if (uniq > 200) score += 150;
    if (score > 1000) score = 1000;
    return score;
}

uint64_t asm_detect_xor_key(const uint8_t *data, size_t size, uint8_t *out_key) {
    uint64_t best_score = 0;
    uint8_t  best_key   = 0;
    for (int k = 0; k < 256; k++) {
        uint64_t score = 0;
        for (size_t i = 0; i < size; i++) {
            uint8_t b = data[i] ^ (uint8_t)k;
            if (b >= 0x20 && b <= 0x7E) score++;
        }
        if (score > best_score) { best_score = score; best_key = (uint8_t)k; }
    }
    if (out_key) *out_key = best_key;
    return best_score;
}

int64_t asm_detect_string_table(const uint8_t *d, size_t sz, size_t min_len, uint64_t *cnt) {
    size_t i = 0, run = 0, strs = 0;
    int64_t first = -1;
    while (i < sz) {
        uint8_t c = d[i];
        if (c >= 0x20 && c <= 0x7E) { run++; i++; continue; }
        if (run >= min_len) { strs++; if (first < 0) first = (int64_t)i; }
        run = 0; i++;
    }
    if (cnt) *cnt = (uint64_t)strs;
    return first;
}
