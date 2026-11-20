# Disclaimer

DFA is early software (v0.1.0). Read this before using its output for any
decision.

## What DFA is not

- **Not legal advice, and no claim of admissibility.** Whether evidence or a
  report is accepted in any proceeding is decided by the court or authority
  concerned, not by a tool.
- **Not a write blocker.** DFA opens images for reading. It cannot prevent
  other software on the analysis host from changing an image file.
- **Not an acquisition tool.** DFA analyses memory images that were already
  acquired. How an image was acquired, and whether it was acquired cleanly,
  is outside DFA's knowledge.
- **Not a validated forensic tool.** No independent party has tested DFA.
  The README lists what has and has not been run on real images.

## Who is responsible

An AI agent using DFA produces a **draft**. A competent human examiner is
responsible for reviewing every tool result, for the interpretation of the
evidence, and for the report. The report names a human examiner of record
for that reason; the agent acted as that person's tool.

Text inside a memory image is controlled by whoever controlled the machine.
DFA labels such text as untrusted, but a label does not stop an agent from
being misled. Review the agent's reasoning, not only its conclusions.

## How to work

- Analyse a working copy. Keep the master copy, and its acquisition hash,
  somewhere DFA cannot reach.
- Compare the image hash DFA records with your acquisition hash yourself;
  DFA does not do this yet.
- A tool error is not a negative result, and a negative result is a
  statement about the plugins that ran, not proof that a system is clean.
- Custody timestamps come from the analysis host's clock, which nothing
  attests.

The current gaps are listed under "Known limitations" in
[README.md](README.md).

## No warranty

DFA is provided under the MIT license, without warranty of any kind. See
[LICENSE](LICENSE).
