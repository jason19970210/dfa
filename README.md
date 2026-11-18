# DFA: Digital Forensics Anything

**An MCP server for memory forensics.** DFA lets a coding agent run
[Volatility 3](https://github.com/volatilityfoundation/volatility3) against a
memory image, and writes every tool call to a hash-chained custody log.

> **Status: v0.1.0, early.** Memory images only. Not on npm yet: install from
> a clone. Read [Known limitations](#known-limitations) and
> [DISCLAIMER.md](DISCLAIMER.md) before relying on any result.

What it does today:

- Runs 26 allow-listed Volatility 3 plugins (9 Windows, 17 Linux) offline,
  with a timeout, an output cap and no shell.
- Marks everything derived from the image as untrusted content, so the agent
  is told not to follow instructions found in process names, command lines
  or shell history.
- Appends one record per successful analysis to a hash-chained JSONL log and
  can verify the chain.
- Renders the log and the examiner's findings as a self-contained HTML report.

## Quick start

Requirements: Node.js 22 or later, Python 3, macOS or Linux.

```bash
git clone https://github.com/jason19970210/dfa.git
cd dfa

# 1. Volatility 3, the analysis engine
python3 -m venv .venv
.venv/bin/pip install volatility3==2.28.2
export DFA_VOL_BIN="$PWD/.venv/bin/vol"

# 2. DFA
npm ci
npm run build

# 3. Check the engine
node dist/main.js doctor
```

`doctor` prints `"ok": true` and exits 0 when Volatility is found.

### First analysis, on a public image

Volatility needs a symbol table that matches the image's kernel (see
[Symbols](#symbols)). The Volatility Foundation publishes a small Linux test
image together with its symbol tables, which is the quickest way to see a
real result:

```bash
mkdir -p ~/dfa-demo/evidence ~/dfa-demo/symbols
cd ~/dfa-demo
base=https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1
curl -LO "$base/linux-sample-1.bin.gz"
curl -LO "$base/linux.zip"
echo "910f272e5eeecdbf229e648d7b136a6722a11a5000f3995647364339417dfddd  linux-sample-1.bin.gz" | shasum -a 256 -c
gunzip -c linux-sample-1.bin.gz > evidence/linux-sample-1.bin
unzip -q linux.zip -d symbols
```

Register DFA with your agent. For Claude Code (use absolute paths):

```bash
claude mcp add dfa \
  -e DFA_VOL_BIN=/absolute/path/to/dfa/.venv/bin/vol \
  -e DFA_SYMBOL_DIRS="$HOME/dfa-demo/symbols" \
  -- node /absolute/path/to/dfa/dist/main.js serve
```

For any other MCP client, the server is a stdio command:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/dfa/dist/main.js", "serve"],
  "env": {
    "DFA_VOL_BIN": "/absolute/path/to/dfa/.venv/bin/vol",
    "DFA_SYMBOL_DIRS": "/home/you/dfa-demo/symbols"
  }
}
```

Then ask the agent to list the processes in
`~/dfa-demo/evidence/linux-sample-1.bin`. `dfa_volatility_linux_pslist`
returns 133 processes; PID 1 is `init`.

## Symbols

DFA always runs Volatility with `--offline`, so analysis never touches the
network. The price is that symbol tables must be on disk first: the
`volatility3` pip package ships none for Windows, Linux or macOS kernels, and
without one every analysis tool except `dfa_volatility_linux_info` fails with
`backend_failed` ("Unable to validate the plugin requirements").

Set `DFA_SYMBOL_DIRS` to one or more directories (separated by `:`). Each
directory holds the layout Volatility expects: a `linux/` or `windows/`
subdirectory containing ISF files (`.json`, `.json.xz`).

- **Linux.** Run `dfa_volatility_linux_info` to read the kernel banner, then
  build the ISF for that exact kernel with
  [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the
  distribution's debug kernel package, and put it under `linux/`. See
  Volatility's
  [symbol tables documentation](https://volatility3.readthedocs.io/en/latest/symbol-tables.html).
- **Windows.** Volatility builds the ISF from a PDB that it downloads from
  Microsoft's symbol server. DFA blocks that download during analysis, so the
  ISF has to be produced beforehand and placed under `windows/`. A
  provisioning command for this is planned (see [ROADMAP.md](ROADMAP.md));
  until then the Windows path is manual and has not been exercised by this
  project on a real image.

## Tools (MCP)

| Tool | Volatility plugin |
|---|---|
| `dfa_volatility_info` | `windows.info` |
| `dfa_volatility_pslist`, `dfa_volatility_pstree`, `dfa_volatility_psscan` | `windows.pslist`, `windows.pstree`, `windows.psscan` |
| `dfa_volatility_malfind` | `windows.malfind` |
| `dfa_volatility_netscan` | `windows.netscan` |
| `dfa_volatility_cmdline`, `dfa_volatility_dlllist`, `dfa_volatility_filescan` | `windows.cmdline`, `windows.dlllist`, `windows.filescan` |
| `dfa_volatility_linux_*` (17 tools) | `banners` (as `linux_info`), `linux.pslist`, `pstree`, `psscan`, `malfind`, `sockstat`, `sockscan`, `psaux`, `bash`, `envars`, `lsmod`, `lsof`, `mountinfo`, `check_afinfo`, `check_syscall`, `check_modules`, `tty_check` |
| `dfa_doctor` | Engine availability check |
| `dfa_custody_verify` | Verify the custody hash chain |
| `dfa_report_generate` | Write the HTML report |

Analysis tools do not modify the image; each successful call appends one
record to the custody log. Large results are returned 200 rows at a time
(`offset` pages through them).

## Custody log

Every successful analysis appends one JSON line to `~/.dfa/custody.jsonl`:

```
seq | ts | tool | argsHash | evidenceHash (image SHA-256) | outputHash | detail | prevHash | hash
```

Each record's `hash` covers the record and the previous record's hash.
`dfa_custody_verify` (or `node dist/main.js report --verify`) re-walks the
chain and reports the first broken link. What the chain does and does not
detect is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Report

`dfa_report_generate` writes a self-contained HTML file (no external
resources, a restrictive Content-Security-Policy) under `~/.dfa/reports/`:
case information, evidence inventory, custody timeline, methodology, findings
and limitations, with a banner showing whether the chain verifies. It never
overwrites an existing file. Findings should cite custody sequence numbers
and state their limitations.

## Evidence handling

- Analyse a working copy of the image, never the master copy.
- DFA does not replace a write blocker. It opens the image for reading and
  cannot stop other processes on the host from changing the file.
- Timestamps in the custody log come from the analysis host's clock.
- DFA does not acquire memory. It analyses images that were already acquired.

## Known limitations

- **One custody log for everything.** All cases on a machine share
  `~/.dfa/custody.jsonl`, and a report lists every record in it. Until cases
  are separated, use a different `DFA_HOME` per case.
- **The image hash is not checked against an acquisition hash.** DFA hashes
  the image after each analysis (cached by file size and modification time)
  and records the result. Compare it with your acquisition hash yourself.
- **No lock on the custody log.** Run one DFA server per `DFA_HOME` at a
  time; two at once can break the chain.
- **The chain detects edited records, not a missing log.** A deleted log, or
  records removed from the end, still verify. Keep the tip hash shown in the
  report somewhere else if you need to detect that.
- **Failed runs are not recorded** in the custody log.
- **Paging re-runs Volatility.** Each page of a large result is a new
  Volatility run and a new custody record.
- **Little has run on real images so far.** `linux_pslist`, `linux_psaux`
  and `linux_info` were run by hand on the public sample above. The other
  Linux tools and all Windows tools have only been tested against a stand-in
  for Volatility.
- **Limits.** Each run is cut off after 10 minutes. The 4 GiB memory cap
  applies on Linux hosts only.
- **Dependency advisory.** `npm audit` reports a denial-of-service advisory
  for zod 3. DFA only receives input from the local MCP client; the move to
  zod 4 is scheduled.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DFA_VOL_BIN` | `vol` | Path to the Volatility 3 executable |
| `DFA_HOME` | `~/.dfa` | DFA's own writable directory (custody log, reports, Volatility cache) |
| `DFA_SYMBOL_DIRS` | _(unset)_ | Symbol directories, `:`-separated (see [Symbols](#symbols)) |
| `DFA_EVIDENCE_DIR` | _(unset)_ | When set, images must resolve (after following symlinks) under this directory |
| `DFA_CUSTODY_LOG` | `$DFA_HOME/custody.jsonl` | Custody log location |
| `DFA_REPORT_DIR` | `$DFA_HOME/reports` | Where reports are written |

## Skill

`skills/dfir-investigate/` is an agent skill that tells the agent when to use
DFA, the order of a memory investigation, and how to write findings with
evidence and limitations.

## Development

```bash
npm run dev      # stdio MCP server through tsx
npm test         # vitest
npm run lint     # type check
npm run build    # tsc -> dist/
```

Set `DFA_VOL_BIN` when running the tests to include the check that every
allow-listed plugin exists in the installed Volatility; without it that test
is skipped.

See [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md),
[CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md).

## Acknowledgements

- [Volatility 3](https://github.com/volatilityfoundation/volatility3), the memory analysis engine DFA drives.
- [volatility3-test-data](https://github.com/volatilityfoundation/volatility3-test-data), the public sample used in the quick start.
- [REA (Reverse Engineer Anything)](https://github.com/morluto/rea), whose MCP design DFA benchmarks against.

## License

MIT, see [LICENSE](LICENSE).
