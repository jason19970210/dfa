import { execFile } from "node:child_process";
import { describe, expect, it } from "vitest";
import { VOLATILITY_PLUGINS } from "./Volatility3Client.js";

/**
 * Every allow-listed plugin must actually exist in the installed Volatility 3
 * build. Catches renames/removals between Volatility versions (e.g. vol 2.x
 * has no linux.info / linux.netscan / linux.cmdline / linux.env — their
 * roles are covered by banners, linux.sockstat, linux.psaux, linux.envars).
 *
 * Skips gracefully when no vol binary is available (CI without Volatility).
 */
function volBin(): string | null {
  return process.env.DFA_VOL_BIN ?? null;
}

function listPlugins(bin: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    // `vol --help` does not list plugins; an invalid plugin choice makes vol
    // print the full "choose from (...)" list on stderr.
    execFile(bin, ["__dfa_nonexistent_plugin__"], { timeout: 60_000 }, (err, stdout, stderr) => {
      const out = String(stdout) + String(stderr);
      const m =
        out.match(/invalid choice \S+ \(choose from ([^)]+)\)/s) ??
        out.match(/\(choose from ([^)]+)\)/s);
      if (!m) {
        reject(
          new Error(
            `could not parse plugin list from vol (err: ${err?.message ?? "none"})`,
          ),
        );
        return;
      }
      resolve(m[1].split(/,\s*/).map((s) => s.trim()));
    });
  });
}

describe("Volatility3Client plugin allow-list", () => {
  it("every allow-listed plugin exists in the installed Volatility 3", async () => {
    const bin = volBin();
    if (!bin) {
      console.warn("DFA_VOL_BIN not set; skipping plugin existence check");
      return;
    }
    const available = await listPlugins(bin);
    const missing = (Object.values(VOLATILITY_PLUGINS) as string[]).filter(
      (plugin) => !available.some((a) => a === plugin || a.startsWith(plugin + ".")),
    );
    expect(missing).toEqual([]);
  });
});
