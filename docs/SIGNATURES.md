# SIGNATURES.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

---

## Overview

MALCAT contains 18 byte signatures compiled from publicly documented malware
patterns. All matching is exact byte search using `asm_scan_signature` (no
wildcards, no regex). A match means those exact bytes appear somewhere in
the file.

**Important:** A match is an indicator, not a verdict. Read the false positive
notes for each signature before drawing conclusions.

---

## Full Signature Table

| # | Name | Bytes (hex) | Length | Severity | Category |
|---|---|---|---|---|---|
| 1 | Metasploit Meterpreter | `FC 48 83 E4 F0` | 5 | 95 | RAT/Backdoor |
| 2 | Generic Shellcode | `31 C0 50 68` | 4 | 80 | Shellcode |
| 3 | CobaltStrike Beacon | `00×8 BE 00 00 00 00` | 13 | 92 | C2/Backdoor |
| 4 | Ransomware .encrypt | `2E 65 6E 63 72 79 70 74` | 8 | 85 | Ransomware |
| 5 | Rootkit `\Device\` | `5C 44 65 76 69 63 65` | 7 | 70 | Rootkit |
| 6 | Mimikatz | `6D 69 6D 69 6B 61 74 7A` | 8 | 90 | Credential theft |
| 7 | Netsh | `4E 65 74 73 68 00` | 6 | 60 | Lateral movement |
| 8 | CertUtil | `63 65 72 74 75 74 69 6C` | 8 | 75 | LOLBin/Dropper |
| 9 | PowerShell | `70 6F 77 65 72 73 68 65 6C 6C` | 10 | 65 | LOLBin |
| 10 | WScript | `57 53 63 72 69 70 74` | 7 | 55 | Script host |
| 11 | Regsvr32 | `72 65 67 73 76 72 33 32` | 8 | 65 | LOLBin |
| 12 | CreateProcess | `43 72 65 61 74 65 50 72 6F 63 65 73 73` | 13 | 50 | Process injection |
| 13 | WriteProcessMemory | `57 72 69 74 65 50 72 6F 63 65 73 73 4D` | 13 | 75 | Process injection |
| 14 | VirtualAlloc | `56 69 72 74 75 61 6C 41 6C 6C 6F 63` | 12 | 60 | Shellcode loader |
| 15 | LoadLibrary | `4C 6F 61 64 4C 69 62 72 61 72 79` | 11 | 45 | DLL injection |
| 16 | WinHttpOpen | `57 69 6E 48 74 74 70 4F 70 65 6E` | 11 | 70 | C2 comms |
| 17 | eval(base64 | `65 76 61 6C 28 62 61 73 65 36 34` | 11 | 78 | Script obfuscation |
| 18 | -encodedcommand | `2D 65 6E 63 6F 64 65 64 63 6F 6D` | 11 | 72 | PS obfuscation |

---

## Per-Signature Notes

**1 — Meterpreter** (`FC 48 83 E4 F0`)

CLD + stack alignment prologue from the Metasploit x64 stager. Very specific
to this shellcode family. Extremely low false positive rate in practice.

**2 — Generic Shellcode** (`31 C0 50 68`)

`XOR EAX,EAX / PUSH EAX / PUSH imm` — a common stack-string construction
idiom in x86 shellcode. Also appears legitimately in hand-written x86 code
and some compiler outputs. Moderate false positive rate.

**3 — CobaltStrike Beacon** (13-byte null-padding + `BE`)

CobaltStrike beacon default configuration has a region of null padding
followed by a `MOV ESI, imm32` instruction. The 13-byte length reduces
false positives, but any binary with a large null-padded section followed
by `0xBE` would match.

**4 — `.encrypt`** (`2E 65 6E 63 72 79 70 74`)

The ASCII string `.encrypt`. Common in ransomware families as a file
extension suffix. Also appears legitimately in encryption utility documentation,
test files, and software that handles encrypted file formats.

**5 — `\Device\`** (`5C 44 65 76 69 63 65`)

ASCII string `\Device\`. In Windows, this is the kernel object namespace path.
Its presence in a non-driver userland PE is suspicious. Drivers and system
software contain it legitimately.

**6 — Mimikatz** (`6D 69 6D 69 6B 61 74 7A`)

The ASCII string `mimikatz`. Appears in the binary itself, variants that
embed the name, and security tools that reference it. Extremely low false
positive rate outside of security tooling.

**7 — Netsh** (`4E 65 74 73 68 00`)

ASCII string `Netsh` followed by a null byte. Matches any binary that
references the Netsh utility. Moderate false positive rate — appears in
network management software.

**8–11 — CertUtil, PowerShell, WScript, Regsvr32**

ASCII strings for Windows LOLBins (Living Off the Land Binaries). High
false positive rate — these strings appear in legitimate software, installers,
and documentation. A match only becomes meaningful when combined with other
indicators.

**12–15 — API strings (CreateProcess, WriteProcessMemory, VirtualAlloc, LoadLibrary)**

String search, not IAT analysis. These strings appear in the import name
tables of countless legitimate binaries, in documentation embedded in
executables, and in error messages. Treat as very weak indicators only.

**16 — WinHttpOpen**

References the Windows HTTP client API. Matches any software that uses
WinHTTP, including legitimate updaters and browsers.

**17 — eval(base64**

The ASCII sequence `eval(base64` — a telltale sign of base64-encoded
JavaScript or PHP executing its decoded payload. Very common in web shell
malware. Lower false positive rate than the other string signatures.

**18 — -encodedcommand**

Partial match for the PowerShell `-EncodedCommand` parameter, often used
to run base64-encoded PS scripts. Common in both malware and legitimate
administration scripts.

---

## False Positive Rate Estimates

These are rough estimates, not measured values:

| Signature | Estimated FP Rate |
|---|---|
| Meterpreter, CobaltStrike, Mimikatz | < 1% |
| `.encrypt`, `\Device\`, `eval(base64` | 1–5% |
| Netsh, CertUtil, WScript, WinHttpOpen, WriteProcessMemory | 5–20% |
| PowerShell, Regsvr32, VirtualAlloc, LoadLibrary, CreateProcess | 20–50% |

---

## Adding a Signature

In `src/bridge.c`:

```c
// 1. Define the byte pattern
static const uint8_t SIG_MYPATTERN[] = { 0xDE, 0xAD, 0xBE, 0xEF };

// 2. Add to SIG_DB[]
{ SIG_MYPATTERN, 4, "My Pattern Name", "Category", 75 },
```

`NUM_SIGS` is computed from `sizeof(SIG_DB)` automatically.

Severity guidelines:
- 85–100: pattern is very specific; almost no benign files contain it
- 60–84: pattern is fairly specific; rare in benign files
- 40–59: pattern is common in malware but also in legitimate software
- 20–39: weak indicator; only useful in combination with others
