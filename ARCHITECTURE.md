# Architecture

This document describes what exists in v0.1.0. Planned work is in
[ROADMAP.md](ROADMAP.md).

## Overview

DFA is a stdio MCP server written in TypeScript. It exposes one tool per
allow-listed Volatility 3 plugin, plus three tools of its own. It starts
Volatility as a child process, parses its JSON output, records the call in a
custody log and returns the rows to the agent.

```
agent (MCP client)
   |  stdio
   v
src/server        tool catalog, annotations, result envelopes
   |
   +--> src/evidence      resolve the image path
   +--> src/volatility3   build the argv, parse the JSON
   |        +--> src/process   run the child process within limits
   +--> src/custody       append to / verify the hash-chained log
   +--> src/report        render and write the HTML report
```

| Module | Responsibility |
|---|---|
| `src/main.ts` | CLI: `serve` (default), `doctor`, `report`, `--help`, `--version` |
| `src/server/index.ts` | Registers the tools, pages results, builds responses |
| `src/config.ts` | Paths under `DFA_HOME`, symbol directories, Volatility's environment |
| `src/evidence/paths.ts` | Image path resolution |
| `src/volatility3/Volatility3Client.ts` | Plugin allow-list, argv, output parsing, image hash |
| `src/process/runCommand.ts` | Bounded child-process runner |
| `src/custody/CustodyLog.ts` | Canonical JSON, hash chain, verification |
| `src/contracts/` | Error codes and the tool result envelope |
| `src/report/` | Input schemas, HTML rendering, exclusive file creation |
| `skills/dfir-investigate/` | Agent skill: methodology and evidence discipline |

## One analysis call

1. **Path.** The image path is resolved with `realpath` and must be a regular
   file. If `DFA_EVIDENCE_DIR` is set, the resolved path must be inside it.
   Errors: `evidence_not_found`, `evidence_not_regular_file`,
   `evidence_outside_root`.
2. **Run.** Volatility is started without a shell as
   `vol -q --offline --cache-path <DFA_HOME>/cache/volatility3 [-s <dirs>] -f <image> -r json <plugin> [--pid N]`.
   The plugin comes from a fixed allow-list; the only free argument is a
   numeric PID on the tools that accept one. `XDG_CACHE_HOME` points under
   `DFA_HOME`, so Volatility's own cache stays there too.
3. **Limits.** A 10-minute timeout sends SIGTERM to the child's process
   group and SIGKILL five seconds later. Standard output is capped at
   256 MiB; only the last 64 KiB of standard error are kept. On Linux hosts
   with `prlimit`, the child's address space is capped at 4 GiB. Errors:
   `backend_timeout`, `backend_output_too_large`, `backend_failed`.
4. **Parse.** Output must be a JSON array of rows (or the older
   columns/rows object). Empty or malformed output is
   `backend_malformed_output`, never "zero rows".
5. **Hash.** The image's SHA-256 is computed (after the run, and cached by
   size and modification time; see the limitations in the README).
6. **Custody.** One record is appended (next section).
7. **Result.** Up to 200 rows are returned, with the totals, the image hash
   and the custody sequence number and hash, as both text and
   `structuredContent`.

## Custody log

One JSON object per line. Fields: `seq`, `ts`, `tool`, `argsHash`,
`evidenceHash`, `outputHash`, `detail`, `note`, `prevHash`, `hash`.

- `argsHash` and `outputHash` are SHA-256 over canonical JSON (keys sorted
  at every level): of the call's arguments (image path, plugin, Volatility
  argv) and of the full row set.
- `hash = sha256(prevHash + canonicalJson(record without hash))`. The first
  record chains to a fixed genesis string.

Verification re-walks the file and recomputes every hash.

| The chain detects | The chain does not detect |
|---|---|
| A changed field in any record | Deletion of the whole log |
| A removed or reordered record in the middle | Records removed from the end |
| An inserted record | A log rewritten from scratch by someone who can write the file |

Nothing outside the file anchors the tip hash, so the log is tamper-evident
only against changes made without recomputing the chain. The log also has no
lock: two servers writing to the same file can produce duplicate sequence
numbers and break the chain.

## Trust boundaries

- **Evidence is untrusted input.** Process names, command lines, shell
  history and environment variables are attacker-controlled text. Every
  result that carries such data, and every backend error, is marked
  `_meta.provenance.untrusted_content: true` with its source (`evidence`,
  `backend` or `custody`), and the server's instructions tell the agent never
  to follow instructions found there. This is a signal to the client, not an
  enforcement mechanism.
- **Tool annotations are honest hints.** Analysis tools are declared
  `readOnlyHint: false` because they append to the custody log, with
  `destructiveHint: false` and `openWorldHint: false` (Volatility runs
  offline).
- **The agent chooses the path.** With `DFA_EVIDENCE_DIR` unset, any regular
  file the user can read is accepted as an image.
- **Errors are typed.** Failures come back as tool results with
  `isError: true` and a structured `error` (`code`, `category`, `message`,
  `retryable`, `remediation`), so that an error is not mistaken for an empty
  result.

## Report

The report is one HTML file with inline styles, every interpolated value
escaped, and a Content-Security-Policy meta tag (`default-src 'none';
style-src 'unsafe-inline'`). Over MCP the agent supplies a file name only
(`[A-Za-z0-9._-]+.html`); the file is created under the report directory with
`O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, so an existing path or a symlink
is never written through. A report directory that is itself a symlink is
refused (`report_dir_unsafe`).
