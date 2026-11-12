import { CustodyLog, type CustodyRecord } from "../custody/CustodyLog.js";

/**
 * Forensic report generator.
 *
 * Renders a self-contained HTML report (no external resources — nothing to
 * leak, nothing that can rot) from the custody audit log plus examiner input.
 * Print to PDF from the browser for a fixed copy.
 *
 * Admissibility note: this report *supports* evidentiary value by documenting
 * chain of custody, integrity, methodology and limitations. It does not by
 * itself make evidence admissible — that is for the court, on the foundation
 * laid by the human examiner named in the report.
 */

export interface ReportCase {
  id: string;
  examiner: string;
  subject?: string;
  opened?: string;
  notes?: string;
}

export interface ReportFinding {
  id: string;
  observation: string;
  /** Custody sequence numbers supporting this finding. */
  evidence?: number[];
  limitation?: string;
  confidence?: "high" | "medium" | "low";
}

export interface GenerateReportOptions {
  custodyLog: CustodyLog;
  dfaVersion: string;
  case: ReportCase;
  findings: ReportFinding[];
  limitations?: string[];
  generatedAt?: string;
}

export function defaultLimitations(): string[] {
  return [
    "All findings describe the system state at evidence-acquisition time unless corroborated by additional sources.",
    "Memory analysis cannot observe events before acquisition or after it; short-lived processes and connections may be missed.",
    "A negative result (e.g. no injection found) reflects the tools run and their coverage, not proof of cleanliness.",
    "Encrypted network payloads are visible as connections, not content.",
    "Tool output shown inline in agent sessions may be truncated; completeness claims rest on the full outputs hashed in custody.",
  ];
}

function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function short(hash: string | undefined, n = 16): string {
  if (!hash) return "—";
  return hash.length > n ? `${hash.slice(0, n)}…` : hash;
}

interface EvidenceItem {
  evidenceHash: string;
  firstSeq: number;
  firstTs: string;
  tool: string;
  image?: string;
  plugin?: string;
}

function buildEvidenceInventory(records: CustodyRecord[]): EvidenceItem[] {
  const byHash = new Map<string, EvidenceItem>();
  for (const r of records) {
    if (!r.evidenceHash) continue;
    if (!byHash.has(r.evidenceHash)) {
      const detail = (r.detail ?? {}) as { image?: string; plugin?: string };
      byHash.set(r.evidenceHash, {
        evidenceHash: r.evidenceHash,
        firstSeq: r.seq,
        firstTs: r.ts,
        tool: r.tool,
        image: detail.image,
        plugin: detail.plugin,
      });
    }
  }
  return [...byHash.values()].sort((a, b) => a.firstSeq - b.firstSeq);
}

const CSS = `
:root { --ink: #1a1a1a; --muted: #5c5c5c; --line: #d8d8d8; --ok: #0f6b2f; --bad: #a31212; --bg: #ffffff; --wash: #f6f6f4; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: var(--ink); background: var(--bg); margin: 0; padding: 0 0 4rem; line-height: 1.55; }
.wrap { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
header.report-head { border-bottom: 3px solid var(--ink); padding-bottom: 1rem; margin-bottom: 1.5rem; }
header.report-head h1 { margin: 0 0 .25rem; font-size: 1.7rem; }
header.report-head .sub { color: var(--muted); font-size: .95rem; }
.banner { border: 2px solid; border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0; }
.banner.ok { border-color: var(--ok); background: #eef7f0; }
.banner.bad { border-color: var(--bad); background: #fbeeee; }
.banner h2 { margin: 0 0 .4rem; font-size: 1.05rem; }
.banner.ok h2 { color: var(--ok); } .banner.bad h2 { color: var(--bad); }
.banner dl { display: grid; grid-template-columns: 11rem 1fr; gap: .15rem .75rem; margin: .5rem 0 0; font-size: .9rem; }
.banner dt { color: var(--muted); } .banner dd { margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }
h2.sec { font-size: 1.2rem; border-bottom: 1px solid var(--line); padding-bottom: .35rem; margin: 2.2rem 0 1rem; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; margin: .5rem 0 1rem; }
th, td { text-align: left; padding: .5rem .6rem; border: 1px solid var(--line); vertical-align: top; }
th { background: var(--wash); font-weight: 600; }
td.mono, .mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: .82rem; word-break: break-all; }
.finding { border: 1px solid var(--line); border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }
.finding h3 { margin: 0 0 .5rem; font-size: 1rem; }
.conf { display: inline-block; font-size: .75rem; font-weight: 700; border-radius: 999px; padding: .1rem .6rem; margin-left: .5rem; vertical-align: middle; }
.conf.high { background: #eef7f0; color: var(--ok); border: 1px solid var(--ok); }
.conf.medium { background: #fff8e6; color: #8a5b00; border: 1px solid #c99a00; }
.conf.low { background: #fbeeee; color: var(--bad); border: 1px solid var(--bad); }
.kv { display: grid; grid-template-columns: 10rem 1fr; gap: .3rem .75rem; font-size: .92rem; }
.kv dt { color: var(--muted); } .kv dd { margin: 0; }
footer { margin-top: 3rem; border-top: 1px solid var(--line); padding-top: 1rem; color: var(--muted); font-size: .85rem; }
ul.tight li { margin-bottom: .35rem; }
@media print { body { padding: 0; } .wrap { max-width: none; padding: 0; } .banner { break-inside: avoid; } table, .finding { break-inside: avoid; } }
`;

export function generateReportHtml(opts: GenerateReportOptions): string {
  const records = opts.custodyLog.readAll();
  const verification = opts.custodyLog.verify();
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const inventory = buildEvidenceInventory(records);
  const tools = [...new Set(records.map((r) => r.tool))].sort();
  const tipHash = records.length > 0 ? records[records.length - 1].hash : "—";
  const limitations = opts.limitations ?? defaultLimitations();
  const c = opts.case;

  const banner = verification.ok
    ? `<div class="banner ok"><h2>✓ Chain of custody intact</h2>
       <dl>
         <dt>Records verified</dt><dd>${records.length}</dd>
         <dt>Chain tip hash</dt><dd>${esc(tipHash)}</dd>
         <dt>Verified at</dt><dd>${esc(generatedAt)}</dd>
       </dl>
       <p style="font-size:.85rem;color:var(--muted)">Every record's hash chains to the previous one. Re-verify any time with
       <span class="mono">dfa_custody_verify</span> or <span class="mono">dfa-agents report --verify</span>.</p></div>`
    : `<div class="banner bad"><h2>✗ CHAIN OF CUSTODY BROKEN</h2>
       <p>First broken record: seq ${esc(verification.brokenAt ?? "?")} (${esc(verification.reason ?? "unknown reason")}).
       Do not rely on this report until the break is investigated.</p></div>`;

  const evidenceRows =
    inventory.length > 0
      ? inventory
          .map(
            (e) => `<tr>
          <td class="mono">${esc(short(e.evidenceHash, 20))}</td>
          <td>${esc(e.image ?? "—")}</td>
          <td>${esc(e.plugin ?? e.tool)}</td>
          <td class="mono">${esc(e.firstTs)}</td>
          <td>${esc(e.firstSeq)}</td>
        </tr>`,
          )
          .join("\n")
      : `<tr><td colspan="5" style="color:var(--muted)">No evidence-bearing tool calls recorded.</td></tr>`;

  const custodyRows = records
    .map(
      (r) => `<tr>
        <td>${esc(r.seq)}</td>
        <td class="mono">${esc(r.ts)}</td>
        <td>${esc(r.tool)}</td>
        <td class="mono">${esc(short(r.evidenceHash))}</td>
        <td class="mono">${esc(short(r.outputHash))}</td>
        <td>${esc(r.note ?? "")}</td>
      </tr>`,
    )
    .join("\n");

  const findingBlocks =
    opts.findings.length > 0
      ? opts.findings
          .map(
            (f) => `<div class="finding">
          <h3>${esc(f.id)}: ${esc(f.observation.slice(0, 90))}${
            f.confidence ? `<span class="conf ${esc(f.confidence)}">${esc(f.confidence.toUpperCase())}</span>` : ""
          }</h3>
          <dl class="kv">
            <dt>Observation</dt><dd>${esc(f.observation)}</dd>
            <dt>Evidence</dt><dd>${f.evidence && f.evidence.length > 0 ? f.evidence.map((s) => `custody seq ${esc(s)}`).join(", ") : "—"}</dd>
            <dt>Limitation</dt><dd>${esc(f.limitation ?? "—")}</dd>
          </dl>
        </div>`,
          )
          .join("\n")
      : `<p style="color:var(--muted)">No findings recorded.</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>DFA Forensic Report — ${esc(c.id)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
<header class="report-head">
  <h1>DFA Forensic Report</h1>
  <div class="sub">Generated by DFA (Digital Forensics Anything) v${esc(opts.dfaVersion)} · ${esc(generatedAt)}</div>
</header>

${banner}

<h2 class="sec">1. Case information</h2>
<dl class="kv">
  <dt>Case ID</dt><dd>${esc(c.id)}</dd>
  <dt>Examiner</dt><dd>${esc(c.examiner)} <span style="color:var(--muted)">(human examiner of record; the agent acted as their tool)</span></dd>
  ${c.subject ? `<dt>Subject</dt><dd>${esc(c.subject)}</dd>` : ""}
  ${c.opened ? `<dt>Opened</dt><dd>${esc(c.opened)}</dd>` : ""}
  ${c.notes ? `<dt>Notes</dt><dd>${esc(c.notes)}</dd>` : ""}
</dl>

<h2 class="sec">2. Evidence inventory</h2>
<table>
  <thead><tr><th>Evidence SHA-256</th><th>Source image</th><th>First examined by</th><th>First seen (UTC)</th><th>Custody seq</th></tr></thead>
  <tbody>${evidenceRows}</tbody>
</table>
<p style="font-size:.85rem;color:var(--muted)">Acquisition-time and analysis-time hashes must match for each item; any divergence invalidates that item's chain.</p>

<h2 class="sec">3. Chain of custody</h2>
<table>
  <thead><tr><th>Seq</th><th>Timestamp (UTC)</th><th>Tool</th><th>Evidence hash</th><th>Output hash</th><th>Note</th></tr></thead>
  <tbody>${custodyRows}</tbody>
</table>

<h2 class="sec">4. Methodology</h2>
<dl class="kv">
  <dt>Tools used</dt><dd class="mono">${tools.map(esc).join("<br>") || "—"}</dd>
  <dt>DFA version</dt><dd class="mono">${esc(opts.dfaVersion)}</dd>
  <dt>Evidence handling</dt><dd>dfa opens evidence read-only and records the SHA-256 of each image in every custody record. dfa does not yet compare these hashes against an acquisition hash, and no hardware write blocker is used. Timestamps come from the analysis host clock. Each tool call is recorded in the custody log with hashes of its inputs and outputs, chained to the previous record.</dd>
</dl>

<h2 class="sec">5. Findings</h2>
${findingBlocks}

<h2 class="sec">6. Limitations</h2>
<ul class="tight">
${limitations.map((l) => `  <li>${esc(l)}</li>`).join("\n")}
</ul>

<footer>
  <p>This report supports evidentiary value by documenting chain of custody, integrity, methodology and limitations. It does not by itself render evidence admissible — admissibility is determined by the court on the foundation laid by the examiner of record.</p>
  <p>To re-verify: <span class="mono">dfa-agents report --verify --custody &lt;custody.jsonl&gt;</span> or the <span class="mono">dfa_custody_verify</span> MCP tool.</p>
</footer>
</div>
</body>
</html>
`;
}
