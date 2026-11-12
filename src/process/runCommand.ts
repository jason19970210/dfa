import { spawn, spawnSync } from "node:child_process";

export interface RunOptions {
  timeoutMs: number;
  /** Time between SIGTERM and SIGKILL. Default 5000. */
  graceMs?: number;
  /** Stdout beyond this kills the child. Default 256 MiB. */
  maxStdoutBytes?: number;
  /** Only the last maxStderrBytes of stderr are kept. Default 64 KiB. */
  maxStderrBytes?: number;
  signal?: AbortSignal;
  /** Address-space cap for the child, applied via prlimit on Linux. */
  memoryLimitBytes?: number;
  /** Child environment; defaults to the parent's. */
  env?: NodeJS.ProcessEnv;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

let prlimitAvailable: boolean | undefined;

function hasPrlimit(): boolean {
  if (prlimitAvailable === undefined) {
    prlimitAvailable =
      process.platform === "linux" && spawnSync("prlimit", ["--version"], { stdio: "ignore", timeout: 5000 }).status === 0;
  }
  return prlimitAvailable;
}

/**
 * Run a backend process with no shell, bounded output, a timeout that
 * escalates SIGTERM -> SIGKILL, and abort support. Rejects with an Error
 * whose message starts with the dfa error code.
 */
export function runCommand(bin: string, args: string[], opts: RunOptions): Promise<RunResult> {
  const graceMs = opts.graceMs ?? 5000;
  const maxStdout = opts.maxStdoutBytes ?? 256 * 1024 * 1024;
  const maxStderr = opts.maxStderrBytes ?? 64 * 1024;

  // ponytail: memory cap only where prlimit exists (Linux); macOS runs uncapped.
  const [cmd, argv] =
    opts.memoryLimitBytes && hasPrlimit()
      ? ["prlimit", [`--as=${opts.memoryLimitBytes}`, "--", bin, ...args]]
      : [bin, args];

  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new Error("backend_aborted: aborted before start"));
      return;
    }
    // detached: the child leads its own process group, so a kill reaches
    // every descendant vol (or prlimit) started, not just the direct child.
    const child = spawn(cmd, argv, { stdio: ["ignore", "pipe", "pipe"], env: opts.env, detached: true });
    const out: Buffer[] = [];
    let outBytes = 0;
    let errTail = Buffer.alloc(0);
    let failure: Error | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    let drainTimer: NodeJS.Timeout | undefined;
    let exitCode: number | null = null;
    let exitSignal: NodeJS.Signals | null = null;
    let settled = false;

    const killGroup = (sig: NodeJS.Signals) => {
      try {
        if (child.pid) process.kill(-child.pid, sig);
      } catch {
        // ESRCH: the group is already gone.
      }
    };

    const stop = (err: Error) => {
      if (failure) return;
      failure = err;
      killGroup("SIGTERM");
      killTimer = setTimeout(() => killGroup("SIGKILL"), graceMs);
    };

    const timer = setTimeout(() => stop(new Error(`backend_timeout: ${bin} exceeded ${opts.timeoutMs} ms`)), opts.timeoutMs);
    const onAbort = () => stop(new Error(`backend_aborted: ${bin} was cancelled`));
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      outBytes += chunk.length;
      if (outBytes > maxStdout) {
        stop(new Error(`backend_output_too_large: ${bin} stdout exceeded ${maxStdout} bytes`));
        return;
      }
      out.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      errTail = Buffer.concat([errTail, chunk]);
      if (errTail.length > maxStderr) errTail = errTail.subarray(errTail.length - maxStderr);
    });

    child.on("error", (err) => stop(new Error(`backend_failed: could not start ${bin}: ${err.message}`)));
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (drainTimer) clearTimeout(drainTimer);
      opts.signal?.removeEventListener("abort", onAbort);
      const stderr = errTail.toString("utf8");
      if (failure) {
        reject(failure);
      } else if (exitCode !== 0) {
        reject(new Error(`backend_failed: ${bin} exited with exit code ${exitCode ?? exitSignal}\nSTDERR: ${stderr}`));
      } else {
        resolve({ stdout: Buffer.concat(out).toString("utf8"), stderr, exitCode: 0 });
      }
    };

    child.on("exit", (code, sig) => {
      exitCode = code;
      exitSignal = sig;
      // Leftover descendants are never wanted; kill them so they release the pipes.
      killGroup("SIGKILL");
      // ponytail: a descendant that left the group (setsid) can still hold the
      // pipes; stop waiting for EOF after 1 s and settle with what was read.
      drainTimer = setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
        settle();
      }, 1000);
    });
    child.on("close", (code, sig) => {
      exitCode ??= code;
      exitSignal ??= sig;
      settle();
    });
  });
}
