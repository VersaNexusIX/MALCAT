# CONTRIBUTING.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

---

## Before You Start

This is a small research and learning project. Contributions are welcome,
but please read this document first so we are aligned on expectations.

---

## Reporting Bugs

Open an issue at https://github.com/VersaNexusIX/MALCAT/issues.

Include:
- OS and architecture (`uname -a`)
- Toolchain versions (`gcc --version`, `as --version`)
- The exact command you ran
- The full output or error message
- If the bug involves a specific file: a description of the file type and
  approximate size (do not upload actual malware samples to the issue tracker)

---

## Suggesting Features

Open an issue tagged `enhancement`. Explain what you want to add and why
it fits the scope of the project (static analysis, ARM64-first, no runtime
dependencies beyond libm).

---

## Pull Requests

```bash
git clone https://github.com/VersaNexusIX/MALCAT
cd MALCAT
git checkout -b your-branch-name
# make your changes
git push origin your-branch-name
# open a PR on GitHub
```

### Requirements for ARM64 Assembly Changes

Any change to `asm/engine.s` must:

- Keep AAPCS64 compliance in every function (save/restore `x19–x28`, `d8–d15`,
  `x29`, `x30`)
- Keep the stack 16-byte aligned at all call boundaries
- Use `.L` prefix for all local labels
- Not introduce comments (project convention: no comments in source files)
- Include a corresponding update to `src/engine_stub.c` with an equivalent
  C implementation
- Include a declaration in `src/bridge.h`
- Include documentation in `docs/ASSEMBLY.md`

### Requirements for C Changes

- C11, no VLAs
- Check every `malloc` and `fopen` return value
- No `sprintf` — use `snprintf` with explicit size
- No global mutable state
- No comments
- Build clean with `-Wall -Wextra`

### Requirements for All Changes

- Build succeeds on ARM64 Linux (full assembly engine)
- Build succeeds on x86-64 Linux (C stub mode)
- No regression on the existing analysis pipeline
- `CHANGELOG.md` updated under `[Unreleased]`
- Relevant `.md` in `docs/` updated if behavior changes

---

## What Is In Scope

- New analysis functions in the assembly engine + C stub
- New file format magic byte detection
- New signatures in the database (with documented FP rate and byte pattern)
- Bug fixes in existing functions
- Documentation improvements
- Build system improvements

## What Is Out of Scope

- Dynamic analysis or sandbox features
- Network connectivity of any kind
- GUI or web interface
- Replacing libm with embedded log2 approximation (use libm for accuracy)
- YARA integration as a runtime dependency

---

## Code Style

No comments in source files. The assembly speaks for itself; the `docs/`
directory is where explanation lives.

Label names in assembly should be descriptive enough to follow logic without
comments. C function names and variable names should be self-explanatory.

---

## Adding a New Signature

1. Add the byte pattern array to `src/bridge.c` above `SIG_DB`.
2. Add an entry to `SIG_DB[]` with name, category, and severity.
3. Add the signature to the table in `docs/SIGNATURES.md` with the hex
   bytes, length, an estimated false positive rate, and a plain-language
   explanation of what the pattern matches and why it is suspicious.

Do not add signatures for bytes that commonly appear in benign software
at a severity above 40.
