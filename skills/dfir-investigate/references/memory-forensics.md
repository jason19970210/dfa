# Memory forensics with DFA (Volatility 3)

## Plugin map — Windows

| Question | Tool | Plugin |
|---|---|---|
| What is this image? | `dfa_volatility_info` | `windows.info` |
| Which processes ran? | `dfa_volatility_pslist` | `windows.pslist` |
| Who spawned whom? | `dfa_volatility_pstree` | `windows.pstree` |
| Any hidden processes? | `dfa_volatility_psscan` | `windows.psscan` |
| Injected code? | `dfa_volatility_malfind` | `windows.malfind` |
| Network activity? | `dfa_volatility_netscan` | `windows.netscan` |
| How was it launched? | `dfa_volatility_cmdline` | `windows.cmdline` |
| What did it load? | `dfa_volatility_dlllist` | `windows.dlllist` |
| File traces? | `dfa_volatility_filescan` | `windows.filescan` |

## Plugin map — Linux

| Question | Tool | Plugin |
|---|---|---|
| What is this image? | `dfa_volatility_linux_info` | `banners` (kernel banner scan) |
| Which processes ran? | `dfa_volatility_linux_pslist` | `linux.pslist` |
| Who spawned whom? | `dfa_volatility_linux_pstree` | `linux.pstree` |
| Any hidden processes? | `dfa_volatility_linux_psscan` | `linux.psscan` |
| Injected code? | `dfa_volatility_linux_malfind` | `linux.malfind` |
| Network activity? | `dfa_volatility_linux_sockstat` / `linux_sockscan` | `linux.sockstat` / `linux.sockscan` |
| How was it launched? | `dfa_volatility_linux_psaux` | `linux.psaux` |
| What did the attacker type? | `dfa_volatility_linux_bash` | `linux.bash` |
| Environment secrets? | `dfa_volatility_linux_envars` | `linux.envars` |
| Kernel modules loaded? | `dfa_volatility_linux_lsmod` | `linux.lsmod` |
| Open files per process? | `dfa_volatility_linux_lsof` | `linux.lsof` |
| Mounts look odd? | `dfa_volatility_linux_mountinfo` | `linux.mountinfo` |
| Network stack hooked? | `dfa_volatility_linux_check_afinfo` | `linux.check_afinfo` |
| Syscalls hooked? | `dfa_volatility_linux_check_syscall` | `linux.check_syscall` |
| Hidden kernel modules? | `dfa_volatility_linux_check_modules` | `linux.check_modules` |
| TTY hooked (keylogger)? | `dfa_volatility_linux_tty_check` | `linux.tty_check` |

Linux notes: a process whose `exe` points at `(deleted)` or a `memfd:` path
is a fileless-execution indicator — pair it with `malfind`. An empty `bash`
history on an interactive-looking host is itself a clue (anti-forensics):
check `history -c` timing against process start times. Always run the
banner `info` first — Volatility needs the right symbol tables, and a wrong
profile yields garbage. Rootkit checks (`check_afinfo`, `check_syscall`, `check_modules`,
`tty_check`) should all read clean on a healthy baseline; any hit is a lead
to corroborate, not a verdict.

## Reading malfind output

`windows.malfind` flags memory regions that are both writable and executable,
or committed as `MEM_PRIVATE` with executable protection — classic signs of
process injection, hollowing, or reflective loading. For each hit, record:

- PID and process name, start/end VPN, protection flags
- Disassembly preview (first bytes) — look for MZ headers, shellcode prologues
- Whether the region maps to a file-backed section (legitimate JIT) or is
  anonymous (suspicious)

A hit is a *lead*, not a verdict. Corroborate with `netscan` (does the process
talk out?) and `dlllist`/`cmdline` before calling it malicious.

## psscan vs pslist

`pslist` walks the kernel's active process list — rootkits unlink entries from
it (DKOM). `psscan` carves `_EPROCESS` structures from pool memory directly.
A process visible in `psscan` but absent from `pslist` is a strong
hiding indicator. Always run both and diff.

## Known limitations to cite

- All results describe the system **at acquisition time**; nothing about
  before/after unless corroborated by logs.
- `netscan` misses short-lived connections that closed before acquisition.
- Encrypted C2 payloads are visible as connections, not content.
- Volatility needs the right symbol tables; a wrong profile yields garbage —
  `info` first, always.
- Inline tool output is truncated at 200 rows; the full result is hashed in
  custody — cite the custody seq, not the truncated view, for completeness
  claims.
