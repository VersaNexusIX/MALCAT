# THREAT_MODEL.md

> **Experimental Research Project** — https://github.com/VersaNexusIX/MALCAT

This document describes honestly what MALCAT can and cannot detect, and the
conditions under which its output is and is not meaningful.

---

## What This Tool Is

MALCAT is a **static triage tool for learning and research**. It was built
to explore ARM64 assembly programming by implementing real analysis functions.
It is not a replacement for dedicated security tools.

---

## What MALCAT Can Reasonably Detect

### Reliable

- Correct identification of file types by magic bytes (PE, ELF, Mach-O, ZIP,
  PDF, and 25+ other formats)
- Very high entropy indicating encryption or compression
- Known exact byte signatures for Meterpreter, Mimikatz, and a small set of
  other well-known patterns
- UPX, ASPack, NSPack, MPRESS packer signatures
- NOP sleds of configurable minimum length
- Files where a single-byte XOR key decodes a large fraction to printable ASCII

### Indicative Only (High False Positive Rate)

- Obfuscation score — tuned by inspection, not against real samples
- LOLBin string matches — also match in many legitimate programs
- Process injection API strings — common in all software that uses these APIs
- Chi-squared uniformity — compressed data also scores low

### Not Reliable

- Polymorphic or metamorphic variants of known malware
- Anything that modifies or omits the byte patterns MALCAT looks for
- Second-stage payloads that are only present in memory at runtime

---

## What MALCAT Cannot Detect

**By design:**
- Runtime behavior (network connections, file modifications, registry changes)
- Code semantics — MALCAT never disassembles or interprets instructions
- Malware embedded within legitimate file formats (e.g. exploit in a PDF object,
  shellcode in a PNG IDAT chunk)
- Encrypted payloads where the key is not a single repeated byte

**Due to missing features:**
- Anything requiring IAT parsing (import table entries without string references)
- Multi-layer packed samples (entropy will be high but MALCAT cannot unpack)
- Unicode (UTF-16LE) strings in PE resources
- Mach-O and DEX malware-specific patterns (no signatures for those yet)

---

## Threat Level Is a Heuristic

The five levels (CLEAN, LOW, MEDIUM, HIGH, CRITICAL) reflect the sum of
heuristic indicators MALCAT found. They are not ground truth.

| Level | What it means |
|---|---|
| CLEAN | No configured indicator triggered. Does not mean the file is safe. |
| LOW | One or two weak indicators. Likely false positive. |
| MEDIUM | Several indicators or one moderate one. Worth more scrutiny. |
| HIGH | Multiple strong indicators or one signature match. Investigate further. |
| CRITICAL | A high-severity signature match plus supporting indicators. |

A sophisticated malware sample that was designed to avoid MALCAT's specific
detection methods would score CLEAN.

---

## Intended Use

MALCAT is suitable for:

- Learning ARM64 assembly by reading its source code
- Quick triage of a batch of files to prioritize which ones to investigate
- Checking whether a file looks like a known format or is unexpectedly binary
- Spotting obviously suspicious characteristics as a first pass

MALCAT is **not** suitable for:

- Making any security decision in isolation
- Classifying a file as definitively clean or definitively malicious
- Replacing antivirus, EDR, sandbox analysis, or manual reverse engineering
- Any production automated pipeline where false positives or false negatives
  have real consequences

---

## Complementary Tools

For actual security analysis, use MALCAT alongside:

| Need | Tool |
|---|---|
| Multi-engine AV | VirusTotal |
| YARA pattern matching | YARA |
| Dynamic analysis | Cuckoo Sandbox, CAPE, ANY.RUN |
| Reverse engineering | Ghidra, Binary Ninja, IDA |
| PE analysis | PE-bear, pestudio |
| Memory forensics | Volatility |
| Network captures | Wireshark |
