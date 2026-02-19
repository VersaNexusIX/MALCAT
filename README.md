# MALCAT

> **⚠ Experimental Research Project** — This is a learning and research tool.
> Not intended for production security workflows. See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for honest limitations.

```
  ╔══════════════════════════════════════════════════════════════╗
  ║  ✦  M A L C A T  v2.0  ✦  Malware Analysis Toolkit        
  ║  ✧ Universal File Forensics ✧ Deep Heuristics ✧ Chi² Stats ✧
  ║       ARM64 Asm · C · Zig  |  All File Types  |  uwu edition 
  ╚══════════════════════════════════════════════════════════════╝
```

**Static file analysis toolkit** — ARM64 assembly core, C bridge, Zig/C CLI.
Built as an experiment in writing a meaningful analysis tool primarily in ARM64 assembly.

**Repository:** https://github.com/VersaNexusIX/MALCAT

---

## What It Does

MALCAT reads a file, runs a set of static analyses, and presents results in a
color-coded terminal UI. It does not execute files, make network connections,
or modify anything.

Analyses performed:

- File type identification via magic bytes (30+ formats)
- Shannon entropy computation (real, via `log2` from libm)
- Byte frequency table and Chi-squared statistic
- Signature scan against 18 known-malware byte patterns
- Obfuscation score (0–1000, five independent factors)
- XOR key brute-force (single-byte, 256 iterations)
- PE and ELF header parsing
- Mach-O and ZIP magic detection
- NOP sled detection
- High-entropy block scanning (per 4 KB window)
- Printable string extraction with offsets
- Dangerous Windows API string scan
- Adler-32 and additive checksums

---

## What It Does NOT Do

- Execute or emulate the analyzed file
- Detect polymorphic or metamorphic malware reliably
- Replace dedicated tools like Ghidra, YARA, or VirusTotal
- Parse PE Import Address Tables (string scan only, higher FP rate)
- Handle multi-layer packing beyond surface entropy detection

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full limitations.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│          CLI Layer — Zig / C                 │
│  Interactive menu · color output · charts    │
├──────────────────────────────────────────────┤
│          Bridge Layer — C                    │
│  File I/O · classification · orchestration   │
├──────────────────────────────────────────────┤
│          Core Engine — ARM64 Assembly        │
│  All numeric analysis functions (engine.s)   │
└──────────────────────────────────────────────┘
```

On non-ARM64 hosts, `engine_stub.c` provides equivalent C implementations
so the tool builds and runs correctly everywhere.

---

## Quick Start

```bash
git clone https://github.com/VersaNexusIX/MALCAT
cd MALCAT
make
./malcat /path/to/file
```

The Makefile detects the host architecture automatically:
- `aarch64` → assembles `asm/engine.s`, links with the assembly engine
- anything else → compiles `src/engine_stub.c` as a portable fallback

---

## Building

| Platform | Requirements |
|---|---|
| ARM64 Linux (native) | `gcc`, `as` (GNU Binutils ≥ 2.38), `libm` |
| ARM64 macOS | `clang`, Apple `as` (Xcode CLT) |
| x86-64 Linux | `gcc`, `libm` — C stub used automatically |

For detailed build instructions, options, and cross-compilation see
[docs/BUILD.md](docs/BUILD.md).

---

## Project Layout

```
MALCAT/
├── asm/
│   └── engine.s              ARM64 assembly core engine
├── src/
│   ├── bridge.h              struct definitions and extern declarations
│   ├── bridge.c              C bridge — I/O, classification, analysis pipeline
│   ├── engine_stub.c         portable C fallback for non-ARM64
│   └── main.c                C CLI (fallback UI)
├── zig/
│   └── src/main.zig          Zig CLI (primary UI when zig is available)
├── docs/
│   ├── DESIGN.md
│   ├── ASSEMBLY.md
│   ├── API.md
│   ├── SIGNATURES.md
│   ├── SECURITY.md
│   ├── CONTRIBUTING.md
│   ├── CHANGELOG.md
│   ├── THREAT_MODEL.md
│   ├── BUILD.md
│   └── FAQ.md
└── Makefile
```

---

## Documentation

| File | Contents |
|---|---|
| [DESIGN.md](docs/DESIGN.md) | Architecture decisions and data flow |
| [ASSEMBLY.md](docs/ASSEMBLY.md) | Every ARM64 function documented |
| [API.md](docs/API.md) | C API reference for embedding |
| [SIGNATURES.md](docs/SIGNATURES.md) | Signature database, FP rates, how to add |
| [SECURITY.md](docs/SECURITY.md) | Security policy and responsible disclosure |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Honest limitations and scope |
| [BUILD.md](docs/BUILD.md) | Build instructions for all platforms |
| [FAQ.md](docs/FAQ.md) | Frequently asked questions |

---

## License

MIT — see [LICENSE](LICENSE).
