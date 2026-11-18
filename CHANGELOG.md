# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--help` and `--version` for the CLI.
- A quick start that ends in a real analysis of a public Linux image, and a
  "Symbols" section explaining what Volatility needs when it runs offline.
- "Known limitations" and "Evidence handling" in the README.
- `DISCLAIMER.md`, `SECURITY.md`, this changelog.
- Continuous integration on Linux and macOS.

### Changed

- Volatility now runs with `-q`, so an error is no longer buried in progress
  output.
- The README, `ARCHITECTURE.md` and `ROADMAP.md` describe only what exists:
  memory forensics. All public documents are in English.
- The plugin-existence test is reported as skipped, not passed, when no
  Volatility is configured.
- vitest 5; other dependencies refreshed.
- The npm package no longer includes `ARCHITECTURE.md`; it includes
  `DISCLAIMER.md`.

### Removed

- `windows.netstat` and `windows.handles` from the plugin allow-list. No tool
  ever exposed them.
- `eval/fixtures/batch1`: hashes and ground truth for memory dumps that are
  no longer available.

## [0.1.0] - 2026-11-12

First public version.

- MCP server exposing 26 Volatility 3 plugins (9 Windows, 17 Linux) as
  tools, run offline through a bounded process runner.
- Hash-chained custody log with verification.
- Self-contained HTML report, written without overwriting existing files.
- Untrusted-content provenance on evidence-derived results, typed errors,
  tool annotations.
- `dfir-investigate` agent skill.
