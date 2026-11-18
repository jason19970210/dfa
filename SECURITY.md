# Security policy

## Supported versions

Only the latest commit on `main` is supported. There are no maintained
release branches yet.

## Reporting a vulnerability

Please report privately: on the repository's **Security** tab, choose
**Report a vulnerability** (GitHub private vulnerability reporting).

If that option is not available, open an issue that says only that you have
a security report, with no details, and a maintainer will arrange a private
channel.

Please include the DFA commit, the Volatility version, the host operating
system, and the steps to reproduce.

## Scope

In scope:

- The MCP server and CLI (`src/`), including path handling, the process
  runner, the custody log and the report writer.
- Ways for content inside a memory image to make DFA write outside its own
  directory, run a command, corrupt the custody log, or present
  evidence-derived text to the agent as trusted.
- The agent skill under `skills/`.

Out of scope:

- Vulnerabilities in Volatility 3 itself; report those to the Volatility
  Foundation.
- The limitations already listed in [README.md](README.md).

## What to expect

DFA is maintained by one person. Reports are read, but there is no
guaranteed response time.
