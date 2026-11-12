import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CustodyLog } from "../custody/CustodyLog.js";
import { generateReportHtml } from "./ReportGenerator.js";
import { CaseSchema, FindingsSchema } from "./schema.js";

function seededLog(): CustodyLog {
  const dir = mkdtempSync(join(tmpdir(), "dfa-report-"));
  const log = new CustodyLog(join(dir, "custody.jsonl"));
  log.append({
    tool: "volatility3.info",
    args: { image: "/evidence/mem.img", plugin: "windows.info" },
    evidenceHash: "aaa".repeat(21) + "a",
    output: { OS: "Windows 11" },
    detail: { image: "/evidence/mem.img", plugin: "windows.info" },
  });
  log.append({
    tool: "volatility3.malfind",
    args: { image: "/evidence/mem.img", plugin: "windows.malfind" },
    evidenceHash: "aaa".repeat(21) + "a",
    output: [{ pid: 4242 }],
    detail: { image: "/evidence/mem.img", plugin: "windows.malfind" },
    note: "rows=1",
  });
  return log;
}

describe("generateReportHtml", () => {
  it("renders all sections with an intact chain banner", () => {
    const html = generateReportHtml({
      custodyLog: seededLog(),
      dfaVersion: "0.1.0-test",
      case: { id: "CASE-001", examiner: "J. Hsu", subject: " suspected intrusion" },
      findings: [
        {
          id: "F-01",
          observation: "Injected code region in pid 4242.",
          evidence: [2],
          limitation: "Memory-only view; persistence unknown.",
          confidence: "medium",
        },
      ],
    });
    for (const section of [
      "Chain of custody intact",
      "1. Case information",
      "2. Evidence inventory",
      "3. Chain of custody",
      "4. Methodology",
      "5. Findings",
      "6. Limitations",
      "CASE-001",
      "J. Hsu",
      "F-01",
      "custody seq 2",
    ]) {
      expect(html).toContain(section);
    }
    // No external resources — self-contained.
    expect(html).not.toMatch(/src="http/);
    expect(html).not.toMatch(/href="http/);
    // HTML-escaped: the subject had a leading space and no markup, but check esc works.
    expect(html).toContain("suspected intrusion");
  });

  it("shows a broken-chain banner when tampered", () => {
    const log = seededLog();
    const lines = readFileSync(log.path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[0]);
    rec.note = "forged note";
    lines[0] = JSON.stringify(rec);
    writeFileSync(log.path, lines.join("\n") + "\n");
    expect(log.verify().ok).toBe(false);
    const html = generateReportHtml({
      custodyLog: log,
      dfaVersion: "0.1.0-test",
      case: { id: "CASE-002", examiner: "J. Hsu" },
      findings: [],
    });
    expect(html).toContain("CHAIN OF CUSTODY BROKEN");
  });

  it("escapes HTML in examiner-controlled fields", () => {
    const html = generateReportHtml({
      custodyLog: seededLog(),
      dfaVersion: "0.1.0-test",
      case: { id: "CASE-003", examiner: "<script>alert(1)</script>" },
      findings: [],
    });
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("escapes hostile custody fields, including seq", () => {
    const log = seededLog();
    const lines = readFileSync(log.path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[0]);
    rec.seq = "<img src=x onerror=alert(1)>";
    rec.tool = "<svg onload=alert(2)>";
    rec.note = "<b>n</b>";
    lines[0] = JSON.stringify(rec);
    writeFileSync(log.path, lines.join("\n") + "\n");
    const html = generateReportHtml({
      custodyLog: log,
      dfaVersion: "0.1.0-test",
      case: { id: "CASE-004", examiner: "E" },
      findings: [],
    });
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<svg");
    expect(html).not.toContain("<b>n</b>");
  });

  it("escapes confidence values", () => {
    const html = generateReportHtml({
      custodyLog: seededLog(),
      dfaVersion: "0.1.0-test",
      case: { id: "CASE-005", examiner: "E" },
      findings: [{ id: "F-1", observation: "o", confidence: '"><script>x</script>' as "high" }],
    });
    expect(html).not.toContain("<script>x");
  });

  it("has a restrictive CSP", () => {
    const html = generateReportHtml({ custodyLog: seededLog(), dfaVersion: "t", case: { id: "C", examiner: "E" }, findings: [] });
    expect(html).toContain(
      `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
    );
  });

  it("states evidence handling honestly", () => {
    const html = generateReportHtml({ custodyLog: seededLog(), dfaVersion: "t", case: { id: "C", examiner: "E" }, findings: [] });
    expect(html).not.toContain("No writes were made");
    expect(html).not.toMatch(/integrity is verified/i);
    expect(html).toContain("records the SHA-256 of each image in every custody record");
    expect(html).toContain("does not yet compare these hashes against an acquisition hash");
    expect(html).toContain("no hardware write blocker is used");
    expect(html).toContain("Timestamps come from the analysis host clock");
    expect(html.toLowerCase()).not.toContain("court-ready");
  });
});

describe("report input schemas", () => {
  it("rejects bad findings", () => {
    expect(FindingsSchema.safeParse([{ id: "F", observation: "o", confidence: "certain" }]).success).toBe(false);
    expect(FindingsSchema.safeParse([{ id: "F", observation: "o", evidence: [0] }]).success).toBe(false);
    expect(FindingsSchema.safeParse([{ id: "F", observation: "o", evidence: [2], confidence: "low" }]).success).toBe(true);
  });

  it("requires case id and examiner", () => {
    expect(CaseSchema.safeParse({ id: "C" }).success).toBe(false);
    expect(CaseSchema.safeParse({ id: "C", examiner: "E" }).success).toBe(true);
  });
});
