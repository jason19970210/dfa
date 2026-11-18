import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const version = (JSON.parse(readFileSync(`${root}package.json`, "utf8")) as { version: string }).version;

function cli(...args: string[]): string {
  return execFileSync(process.execPath, ["--import", "tsx", "src/main.ts", ...args], { cwd: root, encoding: "utf8" });
}

describe("dfa-agents CLI", () => {
  it("prints the version", () => {
    expect(cli("--version")).toBe(`${version}\n`);
    expect(cli("-v")).toBe(`${version}\n`);
  });

  it("prints usage", () => {
    for (const flag of ["--help", "-h"]) {
      const out = cli(flag);
      for (const word of ["serve", "doctor", "report", "--version"]) expect(out).toContain(word);
    }
  });

  it("rejects unknown commands with exit 2", () => {
    let status: number | null = 0;
    try {
      execFileSync(process.execPath, ["--import", "tsx", "src/main.ts", "bogus"], { cwd: root, stdio: "pipe" });
    } catch (err) {
      status = (err as { status: number | null }).status;
    }
    expect(status).toBe(2);
  });
});
