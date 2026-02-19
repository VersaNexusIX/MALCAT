# DESIGN.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

This document explains the architecture of MALCAT and the reasoning behind
its design decisions. It is written to be honest about trade-offs, not to
oversell what the tool does.

---

## Core Idea

Write a static file analysis tool where the computationally intensive parts
live in ARM64 assembly, with C handling I/O and orchestration, and Zig or C
providing the interactive UI.

The goal was to learn ARM64 assembly by building something non-trivial,
not to produce a production-grade security tool.

---

## Three-Layer Structure

```
Layer 3 — UI (Zig / C)
  Interactive menu, ANSI color output, bar charts, hex dump.
  Calls bridge functions. No analysis logic here.

Layer 2 — Bridge (src/bridge.c, src/bridge.h)
  File I/O via fread. Magic-byte classification. Orchestration of
  analysis steps. Signature database. Threat score calculation.
  Calls assembly engine functions.

Layer 1 — Core Engine (asm/engine.s)
  All byte-level analysis: entropy, frequency, signature search,
  header parsing, heuristic scoring, checksum, XOR detection.
  No I/O. No malloc. Works only on buffers passed from C.
```

This separation means the assembly engine is fully testable by passing
known byte buffers to it from C, without needing a real file.

---

## Assembly Engine Design Choices

### Calling Convention

Every function in `engine.s` follows AAPCS64 strictly:

- Frame opened with `stp x29, x30, [sp, #-N]!` and `mov x29, sp`
- All callee-saved registers used (`x19–x27`, `d8–d11`) are saved in the
  prologue and restored in the epilogue before `ret`
- Stack pointer remains 16-byte aligned at all times
- Parameters arrive in `x0–x5`; return value in `x0` or `d0`

### `fmov d8, xzr` Instead of `fmov d8, #0.0`

GNU Assembler on Linux does not accept `fmov d8, #0.0` because 0.0 cannot
be encoded as an 8-bit immediate in the ARM64 floating-point immediate form.
The correct idiom to zero a floating-point register is `fmov d8, xzr`,
which moves the zero general-purpose register into the FP register.
This is what the corrected `engine.s` uses.

### Entropy Calls `bl log2`

`asm_compute_entropy` calls `log2` from libm for each non-zero frequency
bucket (maximum 256 calls per file, not per byte). This is the only external
dependency in the assembly engine.

Because `bl log2` may clobber `x0–x18` and `d0–d7`, all in-flight values
are held in callee-saved registers (`x19–x24`, `d8–d11`) before the call
and remain valid across it.

### Stack-Allocated Frequency Tables

`asm_compute_entropy` and `asm_score_obfuscation` each allocate a 1024-byte
frequency table on the stack (`sub sp, sp, #1024`). This size is fixed and
independent of input, so there is no stack overflow risk. The allocation is
cleaned up (`add sp, sp, #1024`) before returning.

`asm_detect_high_entropy_blocks` allocates 256 bytes per block iteration
and restores the stack immediately after evaluating each block.

### Integer Chi-Squared

`asm_compute_chi2` uses integer arithmetic: `(observed - expected)^2 / expected`
with `expected = total / 256`. The squaring step (`mul x7, x7, x7`) makes the
sign irrelevant. The result is a scaled integer, not a true statistical
chi-squared value with floating-point precision. For the purpose of detecting
"is this distribution suspiciously uniform", this is sufficient.

---

## C Bridge Design Choices

### File Loading

`bridge_load_file` uses `stat` to get the file size, `malloc` to allocate
a single buffer, then `fread` to read the whole file at once. The 512 MB
cap is a hard limit to prevent accidents with large disk images.

### Classification by Magic Bytes Only

`bridge_classify_file` matches against hardcoded byte arrays. It does not
look at file extensions. This means a PE renamed to `.pdf` is still detected
as a PE. The tradeoff is that files with truncated or missing headers will
fall through to the text/unknown detection path.

### Threat Score Is a Heuristic, Not a Verdict

`bridge_assess_threat` adds up contributions from entropy, obfuscation
score, NOP sled presence, chi-squared uniformity, and packer hint. The
resulting number and level string are indicators, not ground truth.
A file scoring `CRITICAL` may be a benign compression utility. A file
scoring `CLEAN` may be sophisticated malware the tool does not know about.

---

## What Was Intentionally Not Built

| Feature | Reason not included |
|---|---|
| PE Import Address Table parsing | Would require significantly more C code; out of scope for this experiment |
| YARA rule support | Separate ecosystem; MALCAT is not trying to replace it |
| Dynamic analysis / sandboxing | Requires executing the file; out of scope by design |
| Aho-Corasick multi-pattern matching | 18 signatures × naïve scan is fast enough; not worth the complexity |
| Recursive archive unpacking | Would need format-specific decompressors |
| Networking of any kind | Not needed; deliberate omission |

---

## Data Flow for Full Analysis

```
path (string)
  │
  ▼ bridge_load_file()
  │   stat() → malloc() → fread()
  ▼ bridge_classify_file()
  │   magic byte matching → is_pe / is_elf / is_macho / ...
  ▼ bridge_analyze_pe() / bridge_analyze_elf()
  │   asm_parse_pe_magic() / asm_parse_elf_magic()
  ▼ bridge_deep_analyze()
  │   asm_byte_frequency()
  │   asm_compute_entropy()          ← calls log2 from libm
  │   asm_count_null_bytes()
  │   asm_count_printable()
  │   asm_suspicious_score()
  │   asm_score_obfuscation()
  │   asm_compute_chi2()
  │   asm_detect_nop_sled()
  │   asm_longest_run()
  │   asm_detect_xor_key()
  │   asm_detect_high_entropy_blocks()
  │   asm_detect_string_table()
  │   asm_compute_checksum()
  │   asm_compute_adler32()
  ▼ bridge_detect_packer()
  │   asm_scan_signature() for UPX/ASPack/NSPack/MPRESS magic
  ▼ bridge_assess_threat()
  │   composite score → threat level string
  ▼ CLI render (main.c / main.zig)
```

---

## Known Weak Points

- Signature scan is byte-exact; any byte change in the pattern defeats it.
- Entropy and chi-squared can be fooled by carefully crafted data.
- The obfuscation score weights were chosen by inspection, not empirical tuning.
- Import scan is string search, not IAT parse, so false positives are common.
- XOR brute-force only covers single-byte keys.
