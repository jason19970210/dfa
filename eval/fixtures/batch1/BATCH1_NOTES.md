# DFA eval fixtures — batch 1 notes

Scenarios: S1 cryptominer, S2 reverse shell / C2 beacon, clean negative control.
Scenario definitions: `eval/SCENARIOS.md` (Tier 1).

## Environment

- Host: no /dev/kvm → QEMU 8.2.2 (Ubuntu noble .debs, extracted to
  `eval/fixtures/work/qemu-root/`) under TCG software emulation.
  - Blocker found and fixed: extracted QEMU could not load `accel-tcg`
    modules (`fatal: could not load module for type 'tcg-accel-ops'`) because
    its baked-in module dir `/usr/lib/x86_64-linux-gnu/qemu` did not exist on
    the host. Fix: `work/boot.sh` now runs QEMU inside `unshare --map-root-user
    --mount` with `qemu-root/usr` bind-mounted over `/usr`. Also merged
    `qemu-root/lib/x86_64-linux-gnu/*.so*` into `qemu-root/usr/lib/x86_64-linux-gnu/`
    (Debian merged-/usr split left `libfuse3.so.3` under `/lib`, invisible after
    the `/usr` over-mount since `/lib` → `/usr/lib`).
- Guest: Ubuntu 24.04 cloud image `noble-server-cloudimg-amd64.img`,
  stock kernel **6.8.0-147-generic** (from serial console banner).
  512 MB RAM, cloud-init nocloud seed (user `ubuntu`, key + password auth).
  Base image booted with `snapshot=on` — never modified.
- Volatility 3.2.28.2 ships **no** Linux ISF symbols (`volatility3/symbols/`
  has only `generic`). ISF for 6.8.0-147-generic is being built with
  `dwarf2json` from the kernel dbgsym ddeb (see `work/isf/`).
- Fake infrastructure (host-side, `work/enact/host_listener.py`):
  - 127.0.0.1:3333 = fake stratum pool (S1). Guest reaches it as 10.0.2.2:3333.
  - 127.0.0.1:4444 = fake C2 (S2). Guest reaches it as 10.0.2.2:4444.

## S1 — cryptominer (done)

- Dump: `s1-cryptominer.mem` (553,781,315 bytes ≈ 528 MB; target was ≤512 MB —
  512 MB guest RAM + ELF header overhead; accepted, noted).
- SHA-256: `3fbdda2cbe4eabc53a4849a0eddb12408edc9fdb6ac749928bde4e85669f6aad`
  (also in `s1-cryptominer.mem.sha256`).
- Enactment (host-driven over SSH, script of record: commands issued 2026-10-18):
  - `/home/ubuntu/xmrig.py` (fake miner, prctl comm=`xmrig`) installed to
    `/usr/local/bin/xmrig.py`, launched via `setsid bash -c 'exec -a xmrig
    /usr/bin/python3 /usr/local/bin/xmrig.py'` → argv[0] disguise.
  - Persistence: `/etc/cron.d/xmrig-miner` → `@reboot root /usr/bin/python3
    /usr/local/bin/xmrig.py`.
- Ground truth: `ground_truth_s1.json` (miner_pid=1546, comm=xmrig,
  pool 10.0.2.2:3333 guest-view / 127.0.0.1:3333 host-view, cron content,
  established-conn `ss` line).
- Host listener log confirms stratum `login` from the guest miner
  (`/tmp/dfa-c2.log`).
- Visibility check: **pending ISF build** — will run `linux.pslist`,
  `linux.netscan`, `linux.cmdline` against the dump once symbols exist.

## S2 — reverse shell / C2 beacon (done)

- Dump: `s2-reverseshell.mem` (553,781,315 bytes).
- SHA-256: `919042566fc3e8353b0c4044a5713f29f8918b22eda4ee64fdbc421e8853ab68`
  (also in `s2-reverseshell.mem.sha256`).
- Enactment script of record: `work/enact/guest_s2.sh` (authored for this run).
  Guest was rebooted fresh for fixture purity (S1 miner must not linger).
- Ground truth: `ground_truth_s2.json` (beacon_pid=1299, ppid=1 at dump,
  C2 10.0.2.2:4444 guest-view / 127.0.0.1:4444 host-view, implant
  `/tmp/.systemd-cache.py`, ESTABLISHED conn line, fake-C2 log excerpt).
- Fake C2 log confirms beacon check-in + `whoami` → `root` round-trip.
- Operational incident 2026-10-18 ~05:06 UTC: the build session
  restarted and killed all `&`-backgrounded processes (QEMU mid-boot, the
  dbgsym curl, host_listener.py). Lesson: launch long-lived processes with
  `setsid nohup ... &` (fully detached) instead of plain `&`. All relaunched
  detached. Note: ddebs.ubuntu.com does NOT support byte ranges — the
  interrupted dbgsym download could not resume (`curl -C -` failed with
  HTTP 33); restarted from scratch.

## Clean negative control (done)

- Dump: `clean-baseline.mem` (553,781,315 bytes).
- SHA-256: `0fd01b1752e248df9be273f2d0a84e0e2b2e7805094a3b80caca6411c2538689`
  (also in `clean-baseline.mem.sha256`).
- Fresh boot, no attack; pre-dump SSH verification: 0 miner/beacon procs,
  no `/etc/cron.d/xmrig-miner`, no conns to 10.0.2.2:3333/4444.
- Ground truth: `ground_truth_clean.json` (expected-absent artifact list).

## Pre-test gates status

1. Scripted enactment + auto ground truth: ✅ S1, ✅ S2, ✅ clean
2. Volatility visibility check: ⏳ blocked on ISF build (dbgsym 1.66 GB;
   first attempt reached 93% in ~1h47m, then a runtime restart killed it;
   ddebs doesn't support resume → restarted from scratch ~00:05 UTC;
   then `work/isf/build_isf.sh`)
3. Negative control: ✅ dumped (analysis TBD once ISF exists)
4. Stability (2× run consistency + plugin runtimes): ⏳ pending
5. Blind test: ⏳ pending (first eval-harness data point)
6. Size check: ⚠️ all three dumps 528 MB (512 MB guest RAM + ELF overhead;
   slightly over target, accepted)

## Engineering fixes found by the visibility check (2026-10-18)

1. **Wrong Linux plugin names**: Volatility 3.2.28 has no `linux.info`,
   `linux.netscan`, `linux.cmdline`, `linux.env`, or `linux.netstat`.
   Remapped: `linux_info`→`banners`, `linux_netscan`→`linux.sockstat`,
   `linux_netstat`→`linux.sockscan`, `linux_cmdline`→`linux.psaux`,
   `linux_env`→`linux.envars`. Added regression test
   `src/volatility3/Volatility3Client.plugins.test.ts` that asserts every
   allow-listed plugin exists in the installed vol build.
2. **Renderer flag**: vol 2.x uses `-r json` (not `--renderer json`), and it
   must precede the plugin name. The scaffold's MCP smoke tests never ran a
   real plugin — only tools/list and error paths — so this went unnoticed.
3. **JSON shape**: vol 3.2 `-r json` emits a bare array of row objects, not
   `{columns, rows}`. `parseVolJson` now handles both shapes.
