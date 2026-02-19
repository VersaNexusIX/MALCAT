# SECURITY.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

---

## Scope

This policy covers the source code in this repository. It does not cover
infrastructure, as this is a standalone offline tool.

---

## What MALCAT Does and Does Not Do

Understanding the tool's behavior is the foundation of its security posture.

**It does:**
- Read a file into a malloc'd buffer once
- Analyze that buffer in memory
- Print results to stdout
- Free the buffer before exit

**It never:**
- Executes or maps the analyzed file as code
- Opens network connections
- Writes to any file on disk
- Spawns child processes
- Calls `system()` or `exec*()`

This means the main attack surface from an analyst's perspective is
malformed input causing unexpected behavior in the parsing or analysis code.

---

## Known Weak Points

### PE Offset Validation

In `asm_parse_pe_magic`, the PE header offset is read from `data[0x3C]`
and validated to be no greater than `0x200`. If a crafted PE sets this
value close to 0x200, the pointer arithmetic `add x5, x0, x4` could
point near the end of the file buffer. There is no subsequent check that
`pe_offset + required_bytes < size` before reading optional header fields.

**Impact:** A carefully crafted file could cause reads slightly beyond the
intended PE header region. The buffer is heap-allocated and followed by
whatever `malloc` placed after it. This is unlikely to cause exploitable
behavior but is a correctness bug.

**Current mitigation:** The 0x200 cap limits how far out of bounds the read
can go.

**Recommended fix for a future version:** Add `if (pe_offset + 96 >= size) goto bad;`
before reading optional header fields.

### Integer Underflow in Chi-Squared

In `asm_compute_chi2`, the subtraction `sub x7, x6, x3` is unsigned.
When `freq[i] < expected`, x7 wraps to a very large 64-bit value. The
subsequent squaring (`mul x7, x7, x7`) makes this even larger, potentially
overflowing. The accumulated chi2 value in x4 could also overflow for files
with unusual byte distributions.

**Impact:** Incorrect chi2 reading for some inputs. No memory safety impact.

### Stack Depth in `asm_detect_high_entropy_blocks`

This function allocates 256 bytes on the stack per iteration and restores it
before the next iteration. The total stack depth at any point is bounded
(frame + 256 bytes), but if called with a very small `block_size`, the number
of iterations could be large. There is no stack overflow risk from this alone,
but it interacts with the host stack limit if the caller is already deeply
nested.

### XOR Brute-Force Performance

For files near the 512 MB limit, `asm_detect_xor_key` performs
`512 * 1024 * 1024 * 256 ≈ 137 billion` byte-level operations. On a
modern ARM64 core this may take tens of seconds. This is a time issue,
not a safety issue, but could be considered a denial-of-service risk if
MALCAT were ever used in an automated pipeline (which is not its intended
use).

---

## Reporting a Vulnerability

This is a small research project. If you find a bug that causes incorrect
behavior or a safety issue, please open a GitHub issue at
https://github.com/VersaNexusIX/MALCAT/issues with the tag `security`.

There is no formal bug bounty program. Responsible disclosure is appreciated.

---

## Build Hardening

The default Makefile uses `-O2 -Wall -Wextra`. For a more hardened build:

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

Note: `-fstack-protector-strong` will add canaries around the large
stack-allocated frequency tables in the assembly functions. The canary
check happens on the C side of the call, not inside the assembly itself.

---

## Legal Note

MALCAT is provided for research and educational purposes. The authors make
no warranty about its fitness for any security-critical use. Output from
MALCAT is heuristic and should not be used as the sole basis for any
security decision.
