# CHANGELOG.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased]

Nothing pending yet.

---

## [2.0.0] — 2025-02-19

### Added — Assembly Engine

- `asm_compute_entropy`: Real Shannon entropy via `bl log2` (libm).
  Previous version used `p*p` accumulation which is not Shannon entropy.
- `asm_byte_frequency`: Standalone frequency table function (256 × uint32).
- `asm_find_all_occurrences`: Returns all match offsets, not just the first.
- `asm_parse_macho_magic`: Detects all five Mach-O magic values using
  `mov` + `movk` to build the 32-bit constants.
- `asm_parse_zip_magic`: Detects PK-archive magic and returns sub-type bytes.
- `asm_compute_adler32`: Adler-32 checksum per RFC 1950.
- `asm_count_null_bytes`: Count 0x00 bytes.
- `asm_count_printable`: Count bytes in [0x20, 0x7E].
- `asm_detect_nop_sled`: Finds runs of 0x90 ≥ configurable minimum.
- `asm_compute_chi2`: Integer chi-squared from pre-built frequency table.
- `asm_detect_string_table`: Finds clusters of printable strings.
- `asm_longest_run`: Longest consecutive run of any given byte value.
- `asm_detect_high_entropy_blocks`: Per-4KB-block distinct-byte count scan.
- `asm_score_obfuscation`: Five-factor obfuscation score 0–1000.
- `asm_detect_xor_key`: Brute-force 256 single-byte XOR keys.

### Added — C Bridge

- `DeepAnalysis` struct centralising all analysis metrics.
- Detection of 30+ file formats via magic bytes (up from 6).
- `bridge_detect_packer`: UPX, ASPack, NSPack, MPRESS detection.
- `bridge_scan_imports`: String scan for 17 dangerous Windows API names.
- `bridge_scan_signatures`: Returns `SigMatch` array with offset and count.
- `FileContext` fields: `mime_type`, `packer_hint`, full `DeepAnalysis`.

### Added — Signature Database

- Expanded from 6 to 18 signatures.
- Added: Netsh, CertUtil, PowerShell, WScript, Regsvr32, CreateProcess,
  WriteProcessMemory, VirtualAlloc, LoadLibrary, WinHttpOpen,
  eval(base64, -encodedcommand.

### Added — CLI

- Menu option [7]: File Type & Format Info.
- Menu option [a]: Suspicious Import Scan.
- Menu option [b]: Byte Frequency Distribution (top 20 with bar chart).
- Menu option [c]: XOR Key Brute-Force with decoded preview.
- Chi-squared bar with interpretation text.
- Obfuscation score bar (0–1000).
- PE timestamp decoded to human-readable date.
- PE subsystem name lookup.
- ELF e_type name lookup.
- File size formatted to B/KB/MB/GB.

### Added — Documentation

Full `docs/` directory: DESIGN.md, ASSEMBLY.md, API.md, SIGNATURES.md,
SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, THREAT_MODEL.md, BUILD.md, FAQ.md.

### Fixed

- `fmov d8, #0.0` in GNU AS Linux → replaced with `fmov d8, xzr`.
  The immediate form of fmov only accepts values encodable as 8-bit FP
  immediates; 0.0 is not one of them in GNU AS.
- `.section __TEXT,__text` macOS syntax removed; `.text` used instead.
- `.globl _asm_*` macOS underscore prefix removed; `.global asm_*` used.
- ELF section header count: ELF64 reads from offset 60, ELF32 from offset 48.
  Previous version read from the same offset for both classes.

### Changed

- `asm_compute_entropy`: Algorithm changed from `p*p` approximation to true
  `H = -Σ p * log2(p)`. Results are now correct Shannon entropy values.
- Signature scan now counts all occurrences of each pattern, not just the first.
- Threat assessment is composite (entropy + obf score + NOP sled + chi2 +
  packer) rather than based on signature matches alone.
- Makefile auto-detects ARM64 vs x86-64 and selects engine accordingly.

---

## [1.0.0] — 2025-02-18

Initial version.

### Assembly Engine

`asm_compute_entropy` (p*p approximation), `asm_scan_signature`, `asm_parse_pe_magic`,
`asm_parse_elf_magic`, `asm_compute_checksum`, `asm_find_pattern`,
`asm_xor_scan`, `asm_suspicious_score`, `asm_rot13`.

### File Classification

PE, ELF, Mach-O, PDF, ZIP, shell script.

### Signatures

6 patterns: Meterpreter, generic shellcode, CobaltStrike, `.encrypt`,
`\Device\`, one generic virus string.

### Known Issues in v1.0

- Assembly used macOS syntax incompatible with GNU AS on Linux.
- `fmov d8, #0.0` invalid in GNU AS.
- Entropy used `p*p` accumulation, not Shannon entropy.
- No packer detection.
- Only 6 signatures.
