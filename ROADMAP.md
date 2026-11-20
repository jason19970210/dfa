# Roadmap

DFA is at v0.1.0. The phases below are in order; none has a date. Each one
ends with a pull request and its own exit criteria.

## A. Honest repository and CI (in progress)

Documentation that states only what the code does, a quick start that ends
in a real result on a public image, known limitations listed in the README,
continuous integration on Linux and macOS, and a refreshed dependency tree.

## B. Validation on public images

A known-answer test lane that runs DFA's tools against the Volatility
Foundation's public Linux and Windows 10 test images and compares the output
with expected values taken from Volatility's own tests. Every claim must pass
twice with identical output hashes, on two different hosts. This is the first
time the Windows tools run on a real image. It shows that DFA reports what
Volatility reports; it is not a claim about detecting attacks.

## C. Evidence model and stable tool names

- Evidence is registered once, with its acquisition hash and metadata, and
  analysed by ID. The image is hashed before analysis and checked again
  afterwards; a change is recorded and stops further use.
- One custody log per case, with a lock, durable writes, detection of
  missing records, and failed runs recorded too.
- Full tool outputs are kept, so paging no longer re-runs Volatility and a
  result can be re-checked against its hash.
- Tool names that do not depend on the operating system, with the OS
  detected at registration.
- An explicit command that fetches and records Windows symbols before
  analysis, so analysis itself stays offline.
- Cancellation, structured logging, a configurable timeout.

Tool names and inputs change in this phase. That is why nothing is published
to npm before it.

## D. First npm release (0.2.0)

`dfa-agents` on npm, a `setup` command for Claude Code and Codex, a `doctor`
that checks symbols, and a validation report for the released version.

## Later

Fixtures of our own that contain attacks, with ground truth generated when
the attack is enacted; evaluation of whole agent investigations; providers
for disk images and timelines.
