# DFA: Digital Forensics Anything

**One MCP server for DFIR across memory, disk, timeline, and network evidence.**

DFA connects your coding agent to forensic tools with a methodology-first
workflow: evidence integrity outranks speed, every conclusion cites its evidence
*and* its limitations, and every tool call is written to a hash-chained
chain-of-custody log.

> MVP (v0.1.0): memory forensics via Volatility 3. Disk (Sleuth Kit), timeline
> (plaso), YARA/EVTX providers and the evaluation harness are next.
> See [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

```bash
# 1. Volatility 3 engine (the analysis backend)
python3 -m venv .venv && .venv/bin/pip install volatility3
export DFA_VOL_BIN="$PWD/.venv/bin/vol"   # or put vol on PATH

# 2. DFA itself
npm install
npm run build

# 3. Check the engine
npx dfa-agents doctor

# 4. Register with your agent (Claude Code example)
# Add to your MCP config:
#   { "command": "node", "args": ["/path/to/dfa/dist/main.js", "serve"] }
```

## Tools (MCP)

| Tool | Purpose |
|---|---|
| `dfa_volatility_info` | OS / image metadata — run first (`windows.info`) |
| `dfa_volatility_pslist` / `pstree` / `psscan` | Process list / tree / hidden processes |
| `dfa_volatility_malfind` | Injected code regions |
| `dfa_volatility_netscan` | Sockets / connections |
| `dfa_volatility_cmdline` / `dlllist` / `filescan` | Cmdlines / loaded DLLs / file objects |
| `dfa_volatility_linux_*` (17 tools) | Linux family: `info` (kernel banners), `pslist`, `pstree`, `psscan`, `malfind`, `sockstat`, `sockscan`, `psaux`, `bash`, `envars`, `lsmod`, `lsof`, `mountinfo`, `check_afinfo`, `check_syscall`, `check_modules`, `tty_check` |
| `dfa_doctor` | Engine availability check |
| `dfa_custody_verify` | Verify custody hash chain |
| `dfa_report_generate` | Generate the forensic HTML report |

All analysis tools are **read-only** against the image. Large outputs are
truncated inline (200 rows); the full output is hashed into custody — cite the
custody sequence number, not the truncated view.

## Forensic report

`dfa_report_generate` (or `dfa-agents report --out report.html`) renders a
self-contained HTML report — no external resources, a restrictive CSP — with
six sections: case information, evidence inventory, chain-of-custody timeline,
methodology, findings, limitations. A banner shows chain integrity
(intact/broken) with the tip hash. Over MCP the tool takes a file `name` and
writes under `~/.dfa/reports/`; neither path ever overwrites an existing file.
Print to PDF from the browser for a fixed copy.
Findings should cite custody seq numbers and state their limitations;
a finding without evidence does not enter the report.

## Chain of custody

Every tool call appends a JSONL record to `~/.dfa/custody.jsonl`
(override with `DFA_CUSTODY_LOG`):

```
seq | tool | argsHash | evidenceHash (image SHA-256) | outputHash | prevHash | hash
```

Each record's hash chains to the previous one. `dfa_custody_verify`
re-walks the chain and reports the first broken link, if any.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DFA_VOL_BIN` | `vol` | Path to the Volatility 3 executable |
| `DFA_HOME` | `~/.dfa` | dfa's own writable directory (custody log, reports, Volatility cache) |
| `DFA_CUSTODY_LOG` | `$DFA_HOME/custody.jsonl` | Custody audit log location |
| `DFA_REPORT_DIR` | `$DFA_HOME/reports` | Where `dfa_report_generate` writes |
| `DFA_SYMBOL_DIRS` | _(unset)_ | Extra Volatility symbol (ISF) directories, `:`-separated. Volatility runs `--offline`, so symbols are never downloaded |
| `DFA_EVIDENCE_DIR` | _(unset)_ | When set, memory images must resolve (realpath) under this directory |

Image SHA-256 hashes are cached per process by path + size + mtime, so
repeated tool calls against the same image don't re-read gigabytes.

## Skill

`skills/dfir-investigate/` — install into your agent for the forensic
workflow: six-phase methodology, evidence discipline, and the
`memory-forensics` reference. It tells the agent *when* to use DFA and how to
report findings with limitations.

## Development

```bash
npm run dev      # tsx, stdio MCP on stdin/stdout
npm test         # vitest
npm run build    # tsc -> dist/
```

## Acknowledgements

- [Volatility 3](https://github.com/volatilityfoundation/volatility3), the memory analysis engine DFA drives.
- [REA (Reverse Engineer Anything)](https://github.com/morluto/rea), whose MCP design DFA benchmarks against.

## License

MIT, see [LICENSE](LICENSE).
