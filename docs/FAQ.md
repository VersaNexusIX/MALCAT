# FAQ.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

---

**Why does the Makefile use the C stub on my ARM64 machine?**

Check `uname -m`. The Makefile switches to the assembly engine only when
the output is exactly `aarch64`. If you are on an ARM64 macOS machine,
`uname -m` returns `arm64`, not `aarch64`, so the stub is used. You can
build the assembly engine manually on macOS if you adapt the assembler
call for Apple LLVM `as` syntax, but `engine.s` as written targets GNU AS.

---

**Why does `fmov d8, #0.0` fail in GNU AS?**

ARM64's `fmov` with an immediate only accepts values that can be encoded
as an 8-bit floating-point immediate (a modified form covering values like
±2.0, ±0.5, etc.). 0.0 is not encodable in that form. The correct way to
zero a floating-point register in GNU AS is `fmov d8, xzr`, which moves
the zero general-purpose register into the FP register. The current
`engine.s` already uses this form.

---

**Can MALCAT tell me definitively whether a file is malware?**

No. MALCAT produces heuristic indicators — entropy, obfuscation score,
signature matches, threat level. These are inputs to an analyst's judgment,
not a verdict. A `CRITICAL` result means several strong indicators were
found; it does not mean the file is definitely malicious. A `CLEAN` result
means none of MALCAT's configured indicators triggered; it does not mean
the file is safe.

---

**The entropy for a ZIP file is very high. Is it malicious?**

Probably not. ZIP files use DEFLATE compression, which produces high entropy
by design — the compressed data looks nearly random. MALCAT's threat
assessment accounts for this by weighting entropy alongside other factors,
but a high entropy reading alone on an archive is expected and normal.

---

**Why does `asm_suspicious_score` look for x86 byte patterns (0x90, 0xCC, 0xEB, 0xE8)?**

The function was written to detect shellcode indicators in x86 binaries.
On an ARM64 ELF, these byte values have no special meaning and the score
will be near zero, which is correct — no x86 shellcode indicators means
no x86 shellcode indicators. The function is not useful for detecting
ARM64-native shellcode, which would require different patterns.

---

**The chi-squared value seems very large or strange for some files.**

`asm_compute_chi2` uses integer arithmetic. When a frequency bucket value
is less than the expected value (`total / 256`), the subtraction wraps
around as an unsigned 64-bit integer, producing a very large number that
then gets squared. This is a known imprecision in the implementation. The
result is still useful for detecting near-uniform distributions (low values)
but can produce unexpectedly large numbers for some inputs. It is not a
statistically correct chi-squared value.

---

**Can I use MALCAT as a library in my own tool?**

Yes. `src/bridge.h` and `src/bridge.c` expose the full analysis pipeline
as callable C functions. See `docs/API.md` for the struct definitions and
function signatures. Link against `engine_stub.c` on non-ARM64 or against
the assembled `engine.o` on ARM64.

---

**Will MALCAT ever get YARA support?**

Not as a runtime dependency. YARA has its own ecosystem and tooling. MALCAT
is intentionally minimal. If there is interest, a future version could export
analysis results in a format that YARA post-processing could consume.

---

**Why no comments in the source code?**

Project convention. The `docs/` directory is where explanation lives.
The assembly label names and C function names are intended to be descriptive
enough to follow without inline comments.

---

**The XOR brute-force is very slow on large files.**

`asm_detect_xor_key` runs O(n × 256) byte operations. For a 100 MB file
this is about 25 billion operations. On a fast ARM64 core it may still take
a noticeable amount of time. A future version could subsample the first
64 KB of the file for this check, which would make it fast while still
finding simple XOR keys in the header region of the file.

---

**What is the difference between `asm_scan_signature` and `asm_find_pattern`?**

`asm_scan_signature` is a naïve two-pointer search that backs up correctly
on mismatch by restoring the outer position to `start_of_partial_match + 1`.
`asm_find_pattern` is a sliding-window search that on mismatch resets the
inner counter to zero without backing up the outer pointer, which means it
can miss overlapping matches. For the non-overlapping case both work
correctly. The signature scanner uses `asm_scan_signature`.
