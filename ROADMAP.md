# Roadmap

DFA is at v0.1.0. It is meant to become a digital forensics and incident
response toolkit that an agent can drive. Memory forensics with Volatility 3
is the first domain and the only one that exists today; the README describes
what works now, this file describes what is planned. Nothing here has a date.

The work is tracked in
[issue #13](https://github.com/jason19970210/dfa/issues/13).

## How the toolkit is put together

- **One server owns the case.** Evidence, runs, retained results, findings
  and reports live in one case record, whatever engine produced them.
- **Engines are separate programs.** DFA starts existing, established tools
  as subprocesses with validated arguments. Each engine is installed
  separately by the user, and a missing engine disables only its own domain.
- **A domain has to add something.** Continuity of evidence across engines,
  reliable and reviewable execution, or findings an agent can assemble across
  domains and a person can check. Another name for an existing command is not
  enough.

## Done

- Documentation that states only what the code does, a quick start that ends
  in a real result on a public image, known limitations in the README, and
  continuous integration on Linux and macOS.

## Foundation

In order. Each item is one issue and one pull request.

1. **Validation on public memory images** (#3). DFA's tools run against the
   Volatility Foundation's public Linux and Windows 10 images on Linux and
   macOS, twice per host, and are compared with expected values and with
   Volatility's own output. It shows that DFA reports what Volatility
   reports; it is not a claim about detecting attacks.
2. **Core contracts** (#4). One registry of operations, a boundary between
   the core and the engines, and types for evidence kinds, file outputs and
   timestamps, so that a new domain is an adapter and not a rework.
3. **Cases and evidence registration** (#5). Evidence is registered in a
   case and hashed before anything is analysed; tools take an evidence ID;
   tool names stop naming the engine and the operating system.
4. **Durable run records** (#6). Every run, including failed, cancelled and
   interrupted ones, is recorded; one writer per case; crashes are detected.
5. **Retained results** (#7). Outputs are kept, so paging and filtering read
   the result of a run that already happened and a finding can point at the
   exact rows it rests on.
6. **Execution and report correctness** (#8). Cancellation, one analysis at
   a time, citations that are checked, a server log.
7. **A second domain, kept small** (#9). Directory listing and file
   extraction from a disk image with The Sleuth Kit, to show that the
   foundation is not memory-specific before anything is published.
8. **Windows symbol provisioning** (#10). One explicit command that fetches
   and records the symbols an image needs; analysis itself stays offline.
9. **Experimental prerelease on npm** (#12), after moving to zod 4 (#11).
   Tool names, inputs and stored formats may still change at that point.

## Domains after the foundation

One at a time, in this order. The engine named is the starting assumption;
the first issue of each domain confirms it together with its licence and its
public test data.

1. **Disk and filesystem** with The Sleuth Kit: partitions, filesystem
   details, directory listing, file metadata, file extraction.
2. **Windows artifacts from disk** with Dissect: event logs, registry,
   Prefetch, Amcache, browser history; then Shimcache, LNK files, jump lists,
   the MFT and the USN journal.
3. **Timeline** with Plaso: a scoped timeline that keeps a reference to the
   source of every event.
4. **Packet captures** with TShark: summary, conversations, DNS, selected
   packets, transferred objects.
5. **YARA and indicator scanning** across registered evidence and extracted
   files.
6. **Linux, then macOS, artifacts from disk.**
7. **Exported cloud and SaaS logs**, offline.
8. **Mobile backups and exports.**
9. **Correlation across artifacts**: explicit, reviewable joins between
   cited observations.

More memory operations on the existing engine (registry hives in memory,
services, scheduled tasks, command history, handles) are added along the way.

## What DFA will not do

Acquire evidence, respond on a live system, remediate, run executables
recovered from evidence, repair or modify evidence, implement its own binary
format parsers, or present an agent's conclusion as established fact.
