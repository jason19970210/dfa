import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CustodyLog, canonicalJson, sha256Hex } from "./CustodyLog.js";

function freshLog(): CustodyLog {
  const dir = mkdtempSync(join(tmpdir(), "dfa-custody-"));
  return new CustodyLog(join(dir, "custody.jsonl"));
}

describe("CustodyLog", () => {
  it("appends chained records and verifies", () => {
    const log = freshLog();
    const r1 = log.append({ tool: "volatility3.pslist", args: { image: "a.img" }, output: [{ pid: 4 }] });
    const r2 = log.append({ tool: "volatility3.malfind", args: { image: "a.img" }, output: [] });
    expect(r2.seq).toBe(2);
    expect(r2.prevHash).toBe(r1.hash);
    expect(log.verify()).toEqual({ ok: true });
    expect(log.readAll()).toHaveLength(2);
  });

  it("detects tampering", () => {
    const log = freshLog();
    log.append({ tool: "volatility3.pslist", args: { image: "a.img" }, output: [{ pid: 4 }] });
    log.append({ tool: "volatility3.malfind", args: { image: "a.img" }, output: [] });
    // Tamper with the first record's output on disk.
    const lines = readFileSync(log.path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[0]);
    rec.note = "forged";
    lines[0] = JSON.stringify(rec);
    writeFileSync(log.path, lines.join("\n") + "\n");
    const res = log.verify();
    expect(res.ok).toBe(false);
    expect(res.brokenAt).toBe(1);
  });

  it("canonicalJson is deterministic regardless of key order", () => {
    const a = canonicalJson({ b: 2, a: 1, nested: { z: 3, y: 4 }, list: [{ q: 1, p: 2 }] });
    const b = canonicalJson({ a: 1, b: 2, nested: { y: 4, z: 3 }, list: [{ p: 2, q: 1 }] });
    expect(a).toBe(b);
    // ...and therefore so are hashes of semantically identical inputs.
    expect(sha256Hex(a)).toBe(sha256Hex(b));
  });
});

describe("canonicalJson hostile keys", () => {
  it("keeps own __proto__ keys", () => {
    expect(canonicalJson(JSON.parse('{"__proto__":{"a":1},"b":2}'))).toBe('{"__proto__":{"a":1},"b":2}');
  });

  it("hashes different __proto__ values differently", () => {
    const a = sha256Hex(canonicalJson(JSON.parse('{"__proto__":1}')));
    const b = sha256Hex(canonicalJson(JSON.parse('{"__proto__":2}')));
    expect(a).not.toBe(b);
  });

  it("leaves ordinary output unchanged", () => {
    expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }] })).toBe('{"a":[{"c":2,"d":1}],"b":1}');
  });
});
