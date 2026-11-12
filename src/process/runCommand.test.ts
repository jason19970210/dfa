import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runCommand } from "./runCommand.js";

const node = process.execPath;
const script = (code: string) => ["-e", code];

describe("runCommand", () => {
  it("returns stdout and exit code", async () => {
    const res = await runCommand(node, script("process.stdout.write('hi')"), { timeoutMs: 10_000 });
    expect(res).toMatchObject({ stdout: "hi", exitCode: 0 });
  });

  it("kills a hung process", async () => {
    const t0 = Date.now();
    await expect(
      runCommand(node, script("setInterval(() => {}, 1000)"), { timeoutMs: 300, graceMs: 300 }),
    ).rejects.toThrow(/^backend_timeout/);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("escalates to SIGKILL when SIGTERM is ignored", async () => {
    const t0 = Date.now();
    await expect(
      runCommand(
        node,
        script("process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"),
        { timeoutMs: 300, graceMs: 300 },
      ),
    ).rejects.toThrow(/^backend_timeout/);
    expect(Date.now() - t0).toBeLessThan(300 + 300 + 1000);
  });

  it("bounds completion when a descendant holds the pipes", async () => {
    // Child spawns a grandchild that inherits stdout/stderr and lives on.
    const code =
      "const c = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' });" +
      "process.stdout.write(String(c.pid)); setInterval(() => {}, 1000)";
    const t0 = Date.now();
    // 300 ms so the grandchild exists before the timeout fires.
    await expect(runCommand(node, script(code), { timeoutMs: 300, graceMs: 100 })).rejects.toThrow(/^backend_timeout/);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("kills the whole process group on timeout", async () => {
    const pidFile = join(mkdtempSync(join(tmpdir(), "dfa-run-")), "gc.pid");
    const code =
      "const c = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });" +
      `require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(c.pid)); setInterval(() => {}, 1000)`;
    await expect(runCommand(node, script(code), { timeoutMs: 300, graceMs: 100 })).rejects.toThrow(/^backend_timeout/);
    const gc = Number(readFileSync(pidFile, "utf8"));
    await new Promise((r) => setTimeout(r, 200));
    let alive = true;
    try {
      process.kill(gc, 0);
    } catch {
      alive = false;
    }
    if (alive) process.kill(gc, "SIGKILL");
    expect(alive).toBe(false);
  });

  it("aborts on signal", async () => {
    const ac = new AbortController();
    const p = runCommand(node, script("setInterval(() => {}, 1000)"), {
      timeoutMs: 10_000,
      graceMs: 200,
      signal: ac.signal,
    });
    setTimeout(() => ac.abort(), 100);
    await expect(p).rejects.toThrow(/^backend_aborted/);
  });

  it("caps stdout", async () => {
    await expect(
      runCommand(node, script("process.stdout.write('x'.repeat(2 * 1024 * 1024))"), {
        timeoutMs: 10_000,
        maxStdoutBytes: 1024 * 1024,
      }),
    ).rejects.toThrow(/^backend_output_too_large/);
  });

  it("keeps only the stderr tail", async () => {
    const res = await runCommand(
      node,
      script("process.stderr.write('a'.repeat(5000) + 'TAIL')"),
      { timeoutMs: 10_000, maxStderrBytes: 100 },
    );
    expect(res.stderr.length).toBeLessThanOrEqual(100);
    expect(res.stderr.endsWith("TAIL")).toBe(true);
  });

  it("reports a non-zero exit with the stderr tail", async () => {
    await expect(
      runCommand(node, script("process.stderr.write('boom'); process.exit(3)"), { timeoutMs: 10_000 }),
    ).rejects.toThrow(/^backend_failed: .*exit code 3.*boom/s);
  });
});
