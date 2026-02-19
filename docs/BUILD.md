# BUILD.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

---

## Requirements by Platform

### ARM64 Linux — native assembly engine

| Tool | Minimum | Check |
|---|---|---|
| GCC | 11.0 | `gcc --version` |
| GNU Binutils as | 2.38 | `as --version` |
| make | 4.0 | `make --version` |
| libm | any | bundled with glibc |

```bash
# Debian/Ubuntu ARM64
sudo apt install gcc binutils make

# Arch Linux ARM
sudo pacman -S gcc binutils make

# Alpine ARM64
apk add gcc binutils make musl-dev
```

### ARM64 macOS — Apple Silicon

The assembly in `engine.s` uses GNU AS syntax. Apple's `as` (LLVM) has
different syntax for some directives and will not assemble `engine.s` without
modification. The C stub build works on macOS:

```bash
# macOS x86-64 or ARM64 (C stub only)
clang -O2 -Isrc src/engine_stub.c src/bridge.c src/main.c -lm -o malcat
```

### x86-64 Linux — C stub fallback

| Tool | Minimum |
|---|---|
| GCC | 9.0 |
| make | 4.0 |
| libm | bundled |

No assembler needed. The Makefile detects `uname -m` and uses the stub
automatically.

---

## Standard Build

```bash
git clone https://github.com/VersaNexusIX/MALCAT
cd MALCAT
make
```

On ARM64 this produces a binary linked against the assembly engine.
On x86-64 this produces a binary using the C stub.

The Makefile prints `[INFO] Not on ARM64 — using portable C stub` if
the stub path is taken.

---

## Manual Build

### ARM64 native

```bash
mkdir -p build
as -march=armv8-a+fp+simd -o build/engine.o asm/engine.s
gcc -O2 -Isrc build/engine.o src/bridge.c src/main.c -lm -o malcat
```

### x86-64 C stub

```bash
gcc -O2 -Isrc src/engine_stub.c src/bridge.c src/main.c -lm -o malcat
```

---

## Optional Zig CLI

If `zig` (≥ 0.12.0) is available, build the Zig UI against a static archive
of the C+ASM layer:

```bash
mkdir -p build

# ARM64
as -march=armv8-a+fp+simd -o build/engine.o asm/engine.s
gcc -c -O2 -Isrc src/bridge.c -o build/bridge.o
ar rcs build/libmalcat.a build/engine.o build/bridge.o

# x86-64
gcc -c -O2 -Isrc src/engine_stub.c -o build/engine.o
gcc -c -O2 -Isrc src/bridge.c -o build/bridge.o
ar rcs build/libmalcat.a build/engine.o build/bridge.o

# Zig CLI
zig build-exe zig/src/main.zig -Isrc -lc build/libmalcat.a \
    -O ReleaseFast -o malcat
```

---

## Hardened Build

```bash
gcc -O2 \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wformat -Wformat-security \
    -fPIE -pie \
    -Wl,-z,relro -Wl,-z,now \
    -Isrc \
    build/engine.o src/bridge.c src/main.c \
    -lm -o malcat
```

---

## Debug Build

```bash
as -march=armv8-a+fp+simd -g -o build/engine.o asm/engine.s
gcc -O0 -g -Isrc -Wall -Wextra \
    build/engine.o src/bridge.c src/main.c -lm -o malcat_dbg
```

Inspect assembly engine in GDB:

```
gdb ./malcat_dbg
(gdb) break asm_compute_entropy
(gdb) run /path/to/testfile
(gdb) info registers
(gdb) x/256wx $x22    # frequency table on stack
```

---

## Cross-Compilation (x86-64 host → ARM64 target)

```bash
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu

aarch64-linux-gnu-as -march=armv8-a+fp+simd -o build/engine.o asm/engine.s
aarch64-linux-gnu-gcc -O2 -Isrc \
    build/engine.o src/bridge.c src/main.c \
    -lm -o malcat_aarch64

file malcat_aarch64
# ELF 64-bit LSB executable, ARM aarch64
```

---

## Verifying the Build

```bash
# Check file type
file malcat

# Check runtime dependencies (should only be libm and libc)
ldd malcat

# Check assembly functions are exported
nm malcat | grep ' T asm_'
# Should list all asm_* functions

# Quick smoke test
echo "q" | ./malcat /bin/ls
```

---

## Common Build Errors

### `junk at end of line, first unrecognized character is '_'`

The assembly file has macOS-style symbol prefixes (`_asm_compute_entropy`).
GNU AS on Linux does not use the underscore prefix. The `engine.s` in this
repository already uses the correct Linux convention. If you see this error,
you may have an old version of `engine.s`.

### `invalid floating-point constant at operand 2 -- fmov d8,#0.0`

The old version of `engine.s` used `fmov d8, #0.0`. GNU AS rejects this
because 0.0 is not encodable as a valid 8-bit FP immediate. The current
`engine.s` uses `fmov d8, xzr` instead.

### `undefined reference to 'log2'`

Missing `-lm` at the end of the link command.
```bash
gcc ... -lm -o malcat
#             ^^^
```

### `cannot find -lm` on Alpine

```bash
apk add musl-dev
```

### Assembly builds on x86-64 but fails to run

The binary would be an ARM64 ELF and will not execute on x86-64.
If you are on x86-64 and want to run MALCAT, use the C stub build —
the Makefile does this automatically.
