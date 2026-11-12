import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Chain-of-custody audit log.
 *
 * Every forensic tool call appends one JSONL record containing hashes of its
 * inputs and outputs, chained to the previous record's hash:
 *
 *   record.hash = sha256(prevHash || canonical(record-without-hash))
 *
 * Tampering with any record breaks the chain, which `verify()` detects.
 * This is the custody backbone every DFA provider writes through.
 */
export interface CustodyRecord {
  seq: number;
  ts: string;
  /** e.g. "volatility3.pslist" */
  tool: string;
  /** Hash of the canonical tool arguments (image path, plugin, flags). */
  argsHash: string;
  /** Hash of the evidence input (e.g. image SHA-256), when known. */
  evidenceHash?: string;
  /** Hash of the canonical tool output. */
  outputHash: string;
  /**
   * Human-readable detail (e.g. {image, plugin}), ALSO covered by the
   * record hash. Kept minimal and non-sensitive: it exists so reports
   * can render without re-running tools.
   */
  detail?: unknown;
  prevHash: string;
  hash: string;
  note?: string;
}

const GENESIS = "dfa-custody-genesis-v1";

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    // Null prototype: assigning an own "__proto__" key to a plain {} would
    // set the prototype instead and silently drop the key from the hash.
    const out = Object.create(null) as Record<string, unknown>;
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export class CustodyLog {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
  }

  private lastHash(): string {
    if (!existsSync(this.path)) return GENESIS;
    const lines = readFileSync(this.path, "utf8").trim().split("\n").filter(Boolean);
    if (lines.length === 0) return GENESIS;
    const last = JSON.parse(lines[lines.length - 1]) as CustodyRecord;
    return last.hash;
  }

  private nextSeq(): number {
    if (!existsSync(this.path)) return 1;
    const lines = readFileSync(this.path, "utf8").trim().split("\n").filter(Boolean);
    return lines.length + 1;
  }

  append(entry: {
    tool: string;
    args: unknown;
    evidenceHash?: string;
    output: unknown;
    detail?: unknown;
    note?: string;
  }): CustodyRecord {
    const prevHash = this.lastHash();
    const body = {
      seq: this.nextSeq(),
      ts: new Date().toISOString(),
      tool: entry.tool,
      argsHash: sha256Hex(canonicalJson(entry.args)),
      evidenceHash: entry.evidenceHash,
      outputHash: sha256Hex(canonicalJson(entry.output)),
      detail: entry.detail,
      prevHash,
      note: entry.note,
    };
    const hash = sha256Hex(prevHash + canonicalJson(body));
    const record: CustodyRecord = { ...body, hash };
    appendFileSync(this.path, canonicalJson(record) + "\n", "utf8");
    return record;
  }

  readAll(): CustodyRecord[] {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as CustodyRecord);
  }

  /** Re-walk the chain; returns the first broken link, or null if intact. */
  verify(): { ok: boolean; brokenAt?: number; reason?: string } {
    const records = this.readAll();
    let prev = GENESIS;
    for (const r of records) {
      if (r.prevHash !== prev) {
        return { ok: false, brokenAt: r.seq, reason: "prevHash mismatch" };
      }
      const { hash, ...body } = r;
      const recomputed = sha256Hex(r.prevHash + canonicalJson(body));
      if (recomputed !== hash) {
        return { ok: false, brokenAt: r.seq, reason: "record hash mismatch" };
      }
      prev = hash;
    }
    return { ok: true };
  }
}
