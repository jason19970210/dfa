#!/usr/bin/env node
import { custodyPath } from "./config.js";
import { Volatility3Client } from "./volatility3/Volatility3Client.js";
import { runStdioServer, DFA_VERSION } from "./server/index.js";

async function doctor(): Promise<void> {
  const vol = new Volatility3Client();
  const res = await vol.checkAvailable();
  console.log(
    JSON.stringify(
      {
        dfa: DFA_VERSION,
        node: process.version,
        volBin: vol.volBin,
        volatility3: res,
        custodyLog: custodyPath(),
      },
      null,
      2,
    ),
  );
  if (!res.ok) process.exitCode = 1;
}

async function reportCmd(rawArgs: string[]): Promise<void> {
  const { CustodyLog } = await import("./custody/CustodyLog.js");
  const { generateReportHtml } = await import("./report/ReportGenerator.js");
  const { DFA_VERSION } = await import("./server/index.js");

  const flag = (name: string): string | undefined => {
    const i = rawArgs.indexOf(name);
    return i >= 0 && i + 1 < rawArgs.length ? rawArgs[i + 1] : undefined;
  };
  const logPath = flag("--custody") ?? custodyPath();
  const log = new CustodyLog(logPath);

  if (rawArgs.includes("--verify")) {
    const res = log.verify();
    console.log(JSON.stringify({ custody: logPath, records: log.readAll().length, ...res }, null, 2));
    if (!res.ok) process.exitCode = 1;
    return;
  }

  const out = flag("--out");
  if (!out) {
    console.error("Usage: dfa-agents report --out <report.html> [--custody <log>] [--case '<json>'] [--findings '<json>']");
    console.error("   or: dfa-agents report --verify [--custody <log>]");
    process.exitCode = 2;
    return;
  }
  const caseJson = flag("--case");
  const findingsJson = flag("--findings");
  const { CaseSchema, FindingsSchema } = await import("./report/schema.js");
  const caseParsed = CaseSchema.safeParse(caseJson ? JSON.parse(caseJson) : { id: "UNFILED", examiner: "UNSET" });
  const findingsParsed = FindingsSchema.safeParse(findingsJson ? JSON.parse(findingsJson) : []);
  if (!caseParsed.success || !findingsParsed.success) {
    console.error(`Invalid --case or --findings: ${(caseParsed.error ?? findingsParsed.error)?.message}`);
    process.exitCode = 2;
    return;
  }
  const c = caseParsed.data;
  const findings = findingsParsed.data;
  const { writeReportExclusive } = await import("./report/writeReport.js");
  const html = generateReportHtml({ custodyLog: log, dfaVersion: DFA_VERSION, case: c, findings });
  writeReportExclusive(out, html);
  const res = log.verify();
  console.log(JSON.stringify({ report: out, records: log.readAll().length, chainOk: res.ok }, null, 2));
}

async function main(): Promise<void> {
  const cmd = process.argv[2] ?? "serve";
  if (cmd === "doctor") {
    await doctor();
    return;
  }
  if (cmd === "report") {
    await reportCmd(process.argv.slice(3));
    return;
  }
  if (cmd === "serve") {
    await runStdioServer();
    return;
  }
  console.error(`Unknown command: ${cmd}\nUsage: dfa-agents [serve|doctor|report]`);
  process.exitCode = 2;
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
