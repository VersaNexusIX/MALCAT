# ASSEMBLY.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

Documentation for every function in `asm/engine.s`.

The file is built with `.arch armv8-a+fp+simd` and targets GNU Assembler on
Linux (GNU Binutils ≥ 2.38). It is **not compatible** with macOS Apple LLVM `as`
without modification.

---

## Calling Convention

All functions follow AAPCS64:

| Registers | Role |
|---|---|
| `x0–x7` | Parameters (input) and return value |
| `x9–x15` | Caller-saved temporaries |
| `x19–x28` | Callee-saved — saved/restored in every function that uses them |
| `x29` | Frame pointer |
| `x30` | Link register |
| `sp` | Stack pointer — must be 16-byte aligned at all call boundaries |
| `d0–d7` | FP parameter / return |
| `d8–d15` | Callee-saved FP — saved/restored if used |
| `d16–d31` | Caller-saved FP |

Every function opens with:
```asm
stp x29, x30, [sp, #-N]!
mov x29, sp
```
and closes with:
```asm
ldp x29, x30, [sp], #N
ret
```

---

## `asm_compute_entropy`

```
int64_t asm_compute_entropy(const uint8_t *data, size_t size, double *out)
```

Returns 0 on success, -1 if size is 0. Writes Shannon entropy (bits) to `*out`.

**Frame:** 128 bytes for callee-saved registers plus `sub sp, sp, #1024` for
the frequency table (256 × uint32).

**Phase 1 — count:** One linear pass over `data`. For each byte value, increment
`freq[byte]` in the on-stack table.

**Phase 2 — entropy:** For each non-zero bucket:
```asm
ucvtf  d10, w9       ; freq[i] → float
fdiv   d10, d10, d9  ; p = freq[i] / size  (d9 = (float)size)
fmov   d0, d10       ; copy p to d0 for the call
bl     log2          ; d0 = log2(p)
fmul   d0, d0, d10   ; d0 = log2(p) * p
fsub   d8, d8, d0    ; H -= log2(p) * p
```

`bl log2` may clobber `x0–x18` and `d0–d7`. All state is held in
callee-saved `x19–x24`, `d8–d11` across the call.

**Zeroing d8:** Uses `fmov d8, xzr` — the correct way to zero a floating-point
register in GNU AS. `fmov d8, #0.0` is **invalid** in GNU AS because 0.0 cannot
be encoded as a valid 8-bit FP immediate.

---

## `asm_byte_frequency`

```
void asm_byte_frequency(const uint8_t *data, size_t size, uint32_t *freq)
```

Fills `freq[256]` with occurrence counts. Clears the table first (256
iterations backward), then one linear pass over data.

---

## `asm_scan_signature`

```
int64_t asm_scan_signature(const uint8_t *data, size_t data_len,
                            const uint8_t *sig, size_t sig_len)
```

Returns offset of first match, or -1. Naïve two-pointer search.

On mismatch at inner position `x11`:
```asm
sub x9, x9, x11   ; back up to before the partial match
add x9, x9, #1    ; advance one
```

---

## `asm_find_all_occurrences`

```
int64_t asm_find_all_occurrences(const uint8_t *data, size_t data_len,
                                  const uint8_t *pattern, size_t pat_len,
                                  int64_t *out_offsets, size_t max_results)
```

Returns count of matches found. Stores each match offset into `out_offsets`.
Used to count how many times a signature appears in a file.

---

## `asm_parse_pe_magic`

```
int64_t asm_parse_pe_magic(const uint8_t *data, PEInfo *out, size_t size)
```

Returns 1 if valid PE, 0 otherwise.

Validation steps:
1. `data[0] == 0x4D`, `data[1] == 0x5A` — MZ magic
2. `*(uint32_t*)(data + 0x3C)` — PE offset, rejected if > 0x200
3. `*(uint32_t*)(data + pe_offset)` — must equal `0x00004550`
4. `*(uint16_t*)(data + pe_offset + 24)` — optional header magic:
   - `0x10B` → PE32 (32-bit); subsystem at PE+0x44, entry at PE+0x60
   - `0x20B` → PE32+ (64-bit); subsystem at PE+0x44, entry at PE+0x70

Fields written to `PEInfo`: machine, timestamp, opt_header_size,
characteristics, subsystem, bitness (32 or 64).

---

## `asm_parse_elf_magic`

```
int64_t asm_parse_elf_magic(const uint8_t *data, size_t size, ELFInfo *out)
```

Returns 1 if valid ELF, 0 otherwise. Validates `\x7FELF` magic, then reads:
- byte 4: `ei_class` (1=ELF32, 2=ELF64)
- byte 5: `ei_data` (1=LE, 2=BE)
- offset 16: `e_type`
- offset 18: `e_machine`
- section count: ELF64 at offset 60, ELF32 at offset 48

---

## `asm_parse_macho_magic`

```
int64_t asm_parse_macho_magic(const uint8_t *data, size_t size, uint32_t *out)
```

Reads the first 4 bytes and checks against five Mach-O magic values. Each
constant is built with `mov` + `movk` because ARM64 cannot encode a 32-bit
constant in a single instruction when the upper 16 bits are non-zero:

```asm
mov  w4, #0xFACE
movk w4, #0xFEED, lsl #16   ; w4 = 0xFEEDFACE
```

| Magic | Meaning |
|---|---|
| `0xFEEDFACE` | Mach-O 32-bit, native endian |
| `0xCEFAEDFE` | Mach-O 32-bit, byte-swapped |
| `0xFEEDFACF` | Mach-O 64-bit, native endian |
| `0xCFFAEDFE` | Mach-O 64-bit, byte-swapped |
| `0xCAFEBABE` | Fat binary (universal) |

---

## `asm_parse_zip_magic`

```
int64_t asm_parse_zip_magic(const uint8_t *data, size_t size, uint8_t *out)
```

Checks `data[0] == 0x50` and `data[1] == 0x4B`. If valid, stores the next
two bytes (the ZIP sub-type indicator) into `out`.

---

## `asm_compute_checksum`

```
uint32_t asm_compute_checksum(const uint8_t *data, size_t size)
```

Simple additive byte sum, masked to 32 bits with `and x0, x2, #0xFFFFFFFF`.

---

## `asm_compute_adler32`

```
uint32_t asm_compute_adler32(const uint8_t *data, size_t size)
```

Adler-32 per RFC 1950. `A = (1 + Σ bytes) mod 65521`, `B = Σ A_i mod 65521`.
Result: `(B << 16) | A`.

Modulo is computed with `udiv` + `msub` since ARM64 has no hardware modulo
instruction.

---

## `asm_count_null_bytes`

```
uint64_t asm_count_null_bytes(const uint8_t *data, size_t size)
```

Single pass; increments counter for each `0x00` byte.

---

## `asm_count_printable`

```
uint64_t asm_count_printable(const uint8_t *data, size_t size)
```

Counts bytes in `[0x20, 0x7E]`. Tab, newline, carriage return are not counted
as printable by this function.

---

## `asm_detect_nop_sled`

```
int64_t asm_detect_nop_sled(const uint8_t *data, size_t size, size_t min_run)
```

Returns the offset of the first run of `0x90` bytes at least `min_run` long,
or -1. Only counts `0x90` (x86 NOP). When a non-0x90 byte is seen, the run
counter resets to 0.

---

## `asm_suspicious_score`

```
int64_t asm_suspicious_score(const uint8_t *data, size_t size)
```

Adds weights for x86 shellcode indicators:

| Byte | Weight | Meaning |
|---|---|---|
| `0x90` | +4 | NOP |
| `0xCC` | +12 | INT3 |
| `0xEB` | +1 | short JMP |
| `0xE8` | +1 | CALL rel32 |

This score is meaningless on non-x86 binaries but does not cause incorrect
results — it just won't detect anything useful in ARM64 or ELF binaries.

---

## `asm_xor_scan`

```
uint64_t asm_xor_scan(const uint8_t *data, size_t size, uint8_t key)
```

XORs each byte with `key` and sums the results. Used as a quick byte-level
hash, not for decryption.

---

## `asm_detect_xor_key`

```
uint64_t asm_detect_xor_key(const uint8_t *data, size_t size, uint8_t *out_key)
```

Tries all 256 single-byte XOR keys. For each key, counts how many bytes
produce a printable ASCII character when XOR'd. Stores the best key in
`*out_key` and returns its printable-byte count.

Complexity: O(n × 256). For a 10 MB file this is about 2.5 billion byte
operations — slow on large files.

---

## `asm_longest_run`

```
uint64_t asm_longest_run(const uint8_t *data, size_t size, uint8_t val)
```

Returns the length of the longest consecutive run of `val` in the data.

---

## `asm_detect_high_entropy_blocks`

```
uint64_t asm_detect_high_entropy_blocks(const uint8_t *data, size_t size,
    size_t block_size, int64_t *out_offsets, size_t max_results)
```

Slides a window of `block_size` bytes. For each window, counts distinct byte
values using a 256-byte boolean table allocated on the stack
(`sub sp, sp, #256`). Windows with more than 250 distinct values are flagged
as high-entropy and their start offsets stored in `out_offsets`.

Threshold of 250 (out of 256 possible) was chosen to reduce false positives
from compressed-but-not-encrypted data.

---

## `asm_score_obfuscation`

```
int64_t asm_score_obfuscation(const uint8_t *data, size_t size)
```

Returns a score in [0, 1000]. Five factors:

| Factor | Max contribution | Description |
|---|---|---|
| Null ratio | 200 | `null_count * 256 / size`, capped at 200 |
| Inverse printable | 120 | `120 - (printable * 256 / size)`, floor 0 |
| Suspicious opcodes | 300 | `opcode_count * 16`, capped at 300 |
| Unique byte count | 30 | +30 if unique bytes > 220 |
| Total | 1000 | Capped at 1000 |

The weights are not empirically derived. They were chosen by inspection
and may produce false positives on legitimate binaries with unusual structure.

---

## `asm_detect_string_table`

```
int64_t asm_detect_string_table(const uint8_t *data, size_t size,
    size_t min_len, uint64_t *out_count)
```

Scans for sequences of at least 5 consecutive printable strings of at least
`min_len` characters each. Returns the offset of the first such cluster, or
-1. Stores the count in `*out_count`.

---

## `asm_compute_chi2`

```
uint64_t asm_compute_chi2(const uint32_t *freq, size_t total)
```

Computes `Σ (freq[i] - expected)^2 / expected` where `expected = total / 256`.
All integer arithmetic. Returns 0 if total is 0 or `expected` rounds to 0.

The subtraction `sub x7, x6, x3` can produce a very large unsigned number
when `freq[i] < expected` (unsigned underflow). The subsequent `mul x7, x7, x7`
squares this large value, giving an unexpectedly large chi-squared for that
bucket. This is a known imprecision in the integer implementation; the result
is still useful as a relative measure of uniformity but does not match a
correct floating-point chi-squared calculation.

---

## `asm_rot13`

```
void asm_rot13(uint8_t *data, size_t size)
```

In-place ROT13. Handles A–Z and a–z separately; other bytes are unchanged.
Uses `udiv` + `msub` for modulo 26.

---

## `asm_find_pattern`

```
int64_t asm_find_pattern(const uint8_t *data, size_t data_len,
                          const uint8_t *pattern, size_t pat_len)
```

Simple sliding-window search. Not a full KMP implementation — on mismatch
after a partial match, the inner counter resets to zero and the outer pointer
does not back up. This can miss matches that overlap with a failed partial
match, but works correctly for the non-overlapping case.
