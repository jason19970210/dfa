import { createHash } from "node:crypto";
import { createReadStream, mkdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { symbolDirs, volCacheDir, volEnv } from "../config.js";
import { resolveEvidencePath } from "../evidence/paths.js";
import { runCommand } from "../process/runCommand.js";

/**
 * Allow-listed Volatility 3 plugins for the MVP (memory-first).
 * Everything runs read-only against the image file; no plugin here
 * writes to the evidence.
 *
 * NOTE: yarascan is intentionally absent — it needs a rules file input
 * that no tool currently supplies. Wire it with a rules parameter or
 * leave it out; do not add it bare.
 */
export const VOLATILITY_PLUGINS = {
  info: "windows.info",
  pslist: "windows.pslist",
  pstree: "windows.pstree",
  psscan: "windows.psscan",
  malfind: "windows.malfind",
  netscan: "windows.netscan",
  netstat: "windows.netstat",
  cmdline: "windows.cmdline",
  dlllist: "windows.dlllist",
  filescan: "windows.filescan",
  handles: "windows.handles",
  // Linux plugins (Volatility 3 linux.*). Same read-only contract: no
  // plugin here writes to the evidence.
  //
  // NOTE on naming vs windows.*: Volatility 3.2 has no linux.info,
  // linux.netscan, linux.cmdline, or linux.env. Their roles are covered by:
  //   linux.info    -> banners        (kernel banner identification)
  //   linux.netscan -> linux.sockstat (socket enumeration; with linux.netstat)
  //   linux.cmdline -> linux.psaux    (process list with command lines)
  //   linux.env     -> linux.envars   (process environment variables)
  linux_info: "banners",
  linux_pslist: "linux.pslist",
  linux_pstree: "linux.pstree",
  linux_psscan: "linux.psscan",
  linux_malfind: "linux.malfind",
  linux_sockstat: "linux.sockstat",
  linux_sockscan: "linux.sockscan",
  linux_psaux: "linux.psaux",
  linux_bash: "linux.bash",
  linux_envars: "linux.envars",
  linux_lsmod: "linux.lsmod",
  linux_lsof: "linux.lsof",
  linux_mountinfo: "linux.mountinfo",
  linux_check_afinfo: "linux.check_afinfo",
  linux_check_syscall: "linux.check_syscall",
  linux_check_modules: "linux.check_modules",
  linux_tty_check: "linux.tty_check",
} as const;

export type VolatilityPluginKey = keyof typeof VOLATILITY_PLUGINS;

export interface VolatilityRunOptions {
  /** Extra CLI args appended after the plugin, e.g. ["--pid", "1234"]. */
  extraArgs?: string[];
  /** Per-run timeout in ms. Defaults to 10 minutes (malfind can be slow). */
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface VolatilityResult {
  plugin: string;
  /** Realpath of the image actually analyzed. */
  image: string;
  imageSha256: string;
  /** Exact vol argv, for custody. */
  volArgs: string[];
  /** Parsed rows from the JSON renderer. */
  rows: Record<string, unknown>[];
  columns: string[];
  /** Raw stderr for diagnostics (truncated). */
  stderr: string;
}

export class Volatility3Client {
  readonly volBin: string;
  /**
   * Image hash cache keyed by resolved path. A cache entry is valid only
   * while size + mtimeMs are unchanged — hashing a multi-GB image on
   * every tool call would dominate runtime.
   */
  private readonly hashCache = new Map<string, { size: number; mtimeMs: number; sha256: string }>();

  constructor(volBin?: string) {
    this.volBin = volBin ?? process.env.DFA_VOL_BIN ?? "vol";
  }

  async checkAvailable(): Promise<{ ok: boolean; version?: string; error?: string }> {
    try {
      const { stdout } = await runCommand(this.volBin, ["--help"], { timeoutMs: 30_000, env: volEnv() });
      const firstLine = stdout.split("\n")[0] ?? "";
      return {
        ok: /volatility/i.test(stdout),
        version: firstLine.trim().slice(0, 120),
      };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /** Full SHA-256 of the image, cached by path+size+mtime. Streams the file; custody demands the real hash. */
  imageSha256(imagePath: string): Promise<string> {
    const st = statSync(imagePath);
    const key = resolve(imagePath);
    const cached = this.hashCache.get(key);
    if (cached && cached.size === st.size && cached.mtimeMs === st.mtimeMs) {
      return Promise.resolve(cached.sha256);
    }
    return new Promise<string>((resolvePromise, reject) => {
      const hash = createHash("sha256");
      const stream = createReadStream(imagePath);
      stream.on("data", (chunk: Buffer | string) => hash.update(chunk));
      stream.on("end", () => {
        const sha256 = hash.digest("hex");
        this.hashCache.set(key, { size: st.size, mtimeMs: st.mtimeMs, sha256 });
        resolvePromise(sha256);
      });
      stream.on("error", reject);
    });
  }

  async run(
    pluginKey: VolatilityPluginKey,
    requestedPath: string,
    options: VolatilityRunOptions = {},
  ): Promise<VolatilityResult> {
    const imagePath = resolveEvidencePath(requestedPath);
    const plugin = VOLATILITY_PLUGINS[pluginKey];
    mkdirSync(volCacheDir(), { recursive: true });
    // Vol-level flags (offline, cache, symbols, -f, -r) must precede the
    // plugin name; plugin-specific args (extraArgs) go after it.
    // --offline: no symbol downloads, so no network and no writes into the
    // vol install; Windows symbols must be provisioned via DFA_SYMBOL_DIRS.
    const args = [
      "--offline",
      "--cache-path",
      volCacheDir(),
      // One semicolon-separated value: vol 2.28.2 keeps only the last of repeated -s flags.
      ...(symbolDirs().length > 0 ? ["-s", symbolDirs().join(";")] : []),
      "-f",
      imagePath,
      "-r",
      "json",
      plugin,
      ...(options.extraArgs ?? []),
    ];
    const { stdout, stderr } = await runCommand(this.volBin, args, {
      timeoutMs: options.timeoutMs ?? 10 * 60 * 1000,
      signal: options.signal,
      memoryLimitBytes: 4 * 1024 * 1024 * 1024,
      env: volEnv(),
    });
    const parsed = parseVolJson(stdout);
    const imageSha256 = await this.imageSha256(imagePath);
    return {
      plugin,
      image: imagePath,
      imageSha256,
      volArgs: args,
      rows: parsed.rows,
      columns: parsed.columns,
      stderr: stderr.slice(0, 2000),
    };
  }
}

function malformed(detail: string): Error {
  return new Error(`backend_malformed_output: vol JSON renderer output ${detail}`);
}

function parseVolJson(stdout: string): { rows: Record<string, unknown>[]; columns: string[] } {
  const trimmed = stdout.trim();
  // An empty result renders as "[]"; empty stdout means vol produced nothing.
  if (!trimmed) throw malformed("was empty");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw malformed("is not JSON");
  }
  // Volatility 3.2+ `-r json` emits a bare array of row objects.
  if (Array.isArray(parsed)) {
    const rows = parsed as Record<string, unknown>[];
    const cols = new Set<string>();
    for (const row of rows) {
      for (const key of Object.keys(row ?? {})) cols.add(key);
    }
    return { rows, columns: [...cols] };
  }
  // Older format: { columns: [{name}], rows: [[values...]] }.
  const obj = parsed as { columns?: { name: string }[]; rows?: unknown[][] };
  if (!Array.isArray(obj?.columns) || !Array.isArray(obj?.rows)) {
    throw malformed("has neither a row array nor columns/rows");
  }
  const columns = obj.columns.map((c) => c.name);
  const rows = obj.rows.map((row) => {
    const o: Record<string, unknown> = {};
    row.forEach((value, i) => {
      o[columns[i] ?? `col${i}`] = value;
    });
    return o;
  });
  return { rows, columns };
}
