---
name: dfir-investigate
description: Investigate a DFIR case with DFA — memory forensics first. Use when a claim depends on evidence inside a memory image, a suspected compromise needs triage, or a forensic timeline/report must be produced from acquired evidence. Skip DFA for ordinary log review that existing SIEM queries already answer.
metadata:
  version: "1"
  tool_count: 29
---

# DFA — dfir-investigate

You are assisting a forensic investigation. Evidence integrity outranks speed.
Every conclusion must cite the evidence behind it **and** the limitations of
that evidence. Never write to an evidence file. Never invent IOCs.

## When to use DFA

Use DFA when the question depends on evidence acquired from a host: a memory
image, and later disk images, event logs, or pcaps. For ordinary analysis of
logs already searchable in a SIEM, use normal tooling and do not reach for DFA.

If DFA tools are unavailable, run `dfa_doctor` first and diagnose the blocker
(Volatility 3 missing, image path wrong, MCP not connected) before continuing.

## Methodology (memory-first MVP)

Follow these phases in order. Do not skip triage.

1. **Identify** — Confirm what the image is: run `dfa_volatility_info`
   (Windows) or `dfa_volatility_linux_info` (Linux). Record OS, build,
   and the image SHA-256 in your notes. Use the matching OS tool family
   for every step below — `dfa_volatility_*` for Windows,
   `dfa_volatility_linux_*` for Linux.
2. **Triage** — `pslist` + `pstree`. Look for: unusual parent-child
   relationships, processes with no image path, system binaries running
   from wrong directories, double extensions (Windows) or `(deleted)` /
   `memfd:` executables (Linux).
3. **Hunt injection** — `malfind` on suspicious PIDs, then `psscan` to
   catch hidden/unlinked processes.
4. **Corroborate** — `netscan` (C2?), `cmdline` (suspicious arguments),
   `dlllist` (unsigned/odd DLLs, Windows), `bash` history + `envars`
   (Linux), `lsmod` vs `check_modules` (hidden kernel modules, Linux).
5. **Report** — Write findings as: observation → evidence (tool + custody
   seq) → limitation → confidence. Every finding must cite custody seq
   numbers — a finding without one does not enter the report. Then generate
   the report with `dfa_report_generate` (or `dfa-agents report --out`):
   it renders case info, evidence inventory, the custody timeline,
   methodology, findings and limitations as a self-contained HTML file —
   print to PDF for a fixed copy. Run `dfa_custody_verify`
   and cite the result. See [memory-forensics](references/memory-forensics.md).

## Evidence discipline

- Quote the custody sequence number for every tool result you rely on.
- State limitations explicitly: e.g. "netscan shows sockets at acquisition
  time only; short-lived connections may be missed."
- A negative result ("no injection found") is a finding about the *tools run*,
  not proof of cleanliness — say which plugins ran and what they cannot see.
- Keep the original image hash from the first tool call; if it ever differs,
  stop and report — the evidence changed under you.
