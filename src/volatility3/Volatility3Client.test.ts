import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeFakeVol, type FakeVol } from "../testing/fakeVol.js";
import { Volatility3Client } from "./Volatility3Client.js";

describe("Volatility3Client", () => {
  let vol: FakeVol;
  let home: string;
  const saved = { ...process.env };

  beforeEach(() => {
    vol = makeFakeVol();
    home = mkdtempSync(join(tmpdir(), "dfa-home-"));
    process.env.DFA_HOME = home;
    delete process.env.DFA_EVIDENCE_DIR;
    delete process.env.DFA_SYMBOL_DIRS;
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it("passes --offline and pinned cache and symbol dirs before the plugin", async () => {
    const symA = join(home, "symA");
    const symB = join(home, "symB");
    mkdirSync(symA);
    mkdirSync(symB);
    process.env.DFA_SYMBOL_DIRS = [symA, symB].join(":");
    await new Volatility3Client(vol.bin).run("linux_pslist", vol.image);
    // vol 2.28.2 takes one semicolon-separated -s value; a repeated -s keeps only the last.
    expect(vol.lastArgv()).toEqual([
      "--offline",
      "--cache-path",
      join(home, "cache", "volatility3"),
      "-s",
      `${symA};${symB}`,
      "-f",
      vol.image,
      "-r",
      "json",
      "linux.pslist",
    ]);
  });

  it("keeps vol's import-time cache under DFA_HOME", async () => {
    const client = new Volatility3Client(vol.bin);
    await client.run("pslist", vol.image);
    expect(vol.lastEnv().XDG_CACHE_HOME).toBe(join(home, "cache"));
    await client.checkAvailable();
    expect(vol.lastEnv().XDG_CACHE_HOME).toBe(join(home, "cache"));
  });

  it("records the exact argv in the result", async () => {
    const res = await new Volatility3Client(vol.bin).run("pslist", vol.image, { extraArgs: ["--pid", "4"] });
    expect(res.volArgs).toEqual(vol.lastArgv());
  });

  it("malformed output is an error", async () => {
    const client = new Volatility3Client(vol.bin);
    vol.setOutput("");
    await expect(client.run("pslist", vol.image)).rejects.toThrow(/^backend_malformed_output/);
    vol.setOutput("{}");
    await expect(client.run("pslist", vol.image)).rejects.toThrow(/^backend_malformed_output/);
    vol.setOutput("not json");
    await expect(client.run("pslist", vol.image)).rejects.toThrow(/^backend_malformed_output/);
  });

  it("an empty array is zero rows", async () => {
    vol.setOutput("[]");
    const res = await new Volatility3Client(vol.bin).run("pslist", vol.image);
    expect(res.rows).toEqual([]);
  });

  it("legacy columns format still parses", async () => {
    vol.setOutput(JSON.stringify({ columns: [{ name: "PID" }, { name: "COMM" }], rows: [[1, "init"]] }));
    const res = await new Volatility3Client(vol.bin).run("pslist", vol.image);
    expect(res.rows).toEqual([{ PID: 1, COMM: "init" }]);
    expect(res.columns).toEqual(["PID", "COMM"]);
  });

  it("checkAvailable reports the version line", async () => {
    const res = await new Volatility3Client(vol.bin).checkAvailable();
    expect(res.ok).toBe(true);
    expect(res.version).toContain("Volatility 3 Framework");
  });
});
