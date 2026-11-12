import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { reportPathForName, writeReportExclusive } from "./writeReport.js";

describe("report output containment", () => {
  let home: string;
  const saved = { ...process.env };

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dfa-home-"));
    process.env.DFA_HOME = home;
    delete process.env.DFA_REPORT_DIR;
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it("rejects unsafe report names", () => {
    for (const name of ["../x.html", "a/b.html", "x.txt", "..", ".html", "a\\b.html", ""]) {
      expect(() => reportPathForName(name), name).toThrow(/^report_name_invalid/);
    }
    expect(existsSync(join(home, "x.html"))).toBe(false);
  });

  it("resolves a plain name under the report directory", () => {
    expect(reportPathForName("case-01.html")).toBe(join(home, "reports", "case-01.html"));
    expect(statSync(join(home, "reports")).mode & 0o777).toBe(0o700);
  });

  it("refuses a report directory that is a symlink", () => {
    const outside = mkdtempSync(join(tmpdir(), "dfa-outside-"));
    symlinkSync(outside, join(home, "reports"));
    expect(() => reportPathForName("case-01.html")).toThrow(/^report_dir_unsafe/);
    expect(readdirSync(outside)).toEqual([]);
  });

  it("never overwrites existing files", () => {
    const custody = join(home, "custody.jsonl");
    writeFileSync(custody, "original");
    expect(() => writeReportExclusive(custody, "<html>")).toThrow(/^report_exists/);
    expect(readFileSync(custody, "utf8")).toBe("original");
  });

  it("refuses a symlink at the target path", () => {
    const victim = join(home, "victim.img");
    writeFileSync(victim, "evidence");
    const link = join(home, "link.html");
    symlinkSync(victim, link);
    expect(() => writeReportExclusive(link, "<html>")).toThrow(/^report_exists/);
    expect(readFileSync(victim, "utf8")).toBe("evidence");
  });

  it("creates a new file with mode 0600", () => {
    const out = join(home, "new.html");
    writeReportExclusive(out, "<html>ok</html>");
    expect(readFileSync(out, "utf8")).toBe("<html>ok</html>");
    expect(statSync(out).mode & 0o777).toBe(0o600);
    expect(readdirSync(home)).toContain("new.html");
  });
});
