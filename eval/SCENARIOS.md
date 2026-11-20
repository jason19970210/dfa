# Evaluation scenarios (design)

> Status: design only. No fixtures are published yet. The first validation
> lane uses the Volatility Foundation's public test images (see
> [ROADMAP.md](../ROADMAP.md), phase B); the scenarios below are for later
> fixtures of our own that contain attacks.

Design rules:

- Every scenario can be enacted in a controlled Linux VM.
- Enactment is scripted, and the script writes the ground truth while it
  runs. Ground truth is a by-product of the enactment, never compiled by hand
  afterwards.
- Every expected artifact must be visible to memory forensics.

## Tier 1: triage basics

### S1. Cryptominer

- **Story:** a server runs a miner that connects out to a pool.
- **Enactment:** a harmless stand-in for a miner connects to a fake pool on
  the host; a cron entry provides persistence.
- **Artifacts:** the miner process, the pool connection, its command line,
  the cron entry.
- **Ground truth:** process name and PID, pool address and port, cron
  content.
- **Tests:** correlating the process list with sockets to answer "who is
  talking to the outside".

### S2. Reverse shell / C2 beacon

- **Story:** after a compromise, a reverse shell beacons home on a timer.
- **Enactment:** a Python reverse shell connects to a listener on the host
  and sleeps between check-ins.
- **Artifacts:** an unusual parent-child chain, an established connection,
  shell history.
- **Ground truth:** C2 address and port, shell PID, the full parent chain.
- **Tests:** reading a process tree and tying it to network state.

## Tier 2: specific techniques

### S3. Fileless execution (memfd_create)

- **Story:** the payload exists only in memory; nothing is on disk.
- **Enactment:** a loader creates an anonymous file with `memfd_create`,
  writes the payload and executes it.
- **Artifacts:** a process whose executable is `memfd:` (deleted), a
  `malfind` hit, anonymous executable mappings.
- **Ground truth:** the memfd name, the PID and address range of the hit.
- **Tests:** injection detection, and the idea that a clean disk is not a
  clean system.

### S4. Web shell

- **Story:** a web shell on a server runs commands for a remote attacker.
- **Enactment:** a minimal HTTP server executes a `cmd` parameter; a few
  commands are issued.
- **Artifacts:** suspicious children of the web server, command lines, the
  client connection.
- **Ground truth:** web shell PID, the command sequence, the client address.
- **Tests:** child-process lineage on a compromised server.

### S5. Ransomware simulation

- **Story:** files in a directory are encrypted and a note is left.
- **Enactment:** a script walks a directory of dummy files, encrypts them
  and writes a note.
- **Artifacts:** the encrypting process, its open files, the note, its
  command line.
- **Ground truth:** PID, number of files, path of the note.
- **Tests:** estimating the extent of the damage.

## Tier 3: reasoning across artifacts

### S6. Insider exfiltration

- **Story:** someone archives data, uploads it, and clears the shell history.
- **Enactment:** `tar` a directory, upload it with `curl` to a listener on
  the host, then `history -c`.
- **Artifacts:** the archive and upload processes, the connection, and the
  cleared history itself (traces may remain in memory).
- **Ground truth:** list of archived files, destination address and port,
  time window.
- **Tests:** whether the investigator notices that an empty history is
  itself a finding.

## Gates before a fixture is published

A fixture is an image, its ground truth and its expected findings.

1. **Scripted enactment.** The attack steps are a script that also writes
   the ground truth (PIDs, addresses, ports, timestamps, paths), separated
   into "at launch" and "at dump" values.
2. **Visibility check.** After the dump, run the relevant plugins by hand
   and confirm each artifact is actually visible. If it is not, the fixture
   is invalid and is re-enacted.
3. **Negative control.** A dump of the same VM in a clean state. The
   expected result is "no findings"; this measures false positives.
4. **Stability.** Two analyses of the same fixture give identical output;
   plugin run times are recorded.
5. **Blind test.** One full investigation without the ground truth, scored
   afterwards.
6. **Size.** Target 512 MB or less per image.
7. **Reproducibility.** The enactment scripts, the VM image reference and
   the symbol table are tracked, so anyone can rebuild the fixture.
