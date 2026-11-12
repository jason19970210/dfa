import { chmodSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A fake `vol` executable for boundary tests: records its argv and prints a
 * configurable stdout payload. Test-only; excluded from the build.
 */
export interface FakeVol {
  bin: string;
  dir: string;
  /** Write the stdout the next vol call prints. */
  setOutput(stdout: string): void;
  /** argv of the most recent vol call. */
  lastArgv(): string[];
  /** Selected environment of the most recent vol call. */
  lastEnv(): { XDG_CACHE_HOME?: string };
  /** A regular file usable as a memory image. */
  image: string;
}

export function makeFakeVol(): FakeVol {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "dfa-fakevol-")));
  const bin = join(dir, "vol");
  const argvFile = join(dir, "argv.json");
  const outFile = join(dir, "stdout.txt");
  const envFile = join(dir, "env.json");
  writeFileSync(
    bin,
    `#!${process.execPath}
const fs = require("node:fs");
fs.writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(process.argv.slice(2)));
fs.writeFileSync(${JSON.stringify(envFile)}, JSON.stringify({ XDG_CACHE_HOME: process.env.XDG_CACHE_HOME }));
if (process.argv.includes("--help")) { process.stdout.write("Volatility 3 Framework 2.28.2 (fake)\\n"); process.exit(0); }
process.stdout.write(fs.existsSync(${JSON.stringify(outFile)}) ? fs.readFileSync(${JSON.stringify(outFile)}, "utf8") : "[]");
`,
  );
  chmodSync(bin, 0o755);
  const image = join(dir, "mem.img");
  writeFileSync(image, "fake memory image");
  return {
    bin,
    dir,
    image,
    setOutput: (stdout) => writeFileSync(outFile, stdout),
    lastArgv: () => JSON.parse(readFileSync(argvFile, "utf8")) as string[],
    lastEnv: () => JSON.parse(readFileSync(envFile, "utf8")) as { XDG_CACHE_HOME?: string },
  };
}
