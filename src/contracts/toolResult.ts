import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { toDfaError } from "./errors.js";

/** Where untrusted bytes came from: the image, the on-disk custody log, or backend output. */
export type UntrustedSource = "evidence" | "custody" | "backend";

function provenance(source: UntrustedSource | false) {
  return { provenance: { untrusted_content: source !== false, source: source || "dfa" } };
}

/** Success result. `source` names where untrusted bytes in the payload came from; false = dfa's own data. */
export function okResult(data: Record<string, unknown>, source: UntrustedSource | false): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    structuredContent: data,
    _meta: provenance(source),
  };
}

/** Failure as a tool result (not a protocol error) so the agent can correct course. */
export function errorResult(err: unknown, source?: UntrustedSource | false): CallToolResult {
  const e = toDfaError(err);
  const error = {
    code: e.code,
    category: e.category,
    message: e.message,
    retryable: e.retryable,
    remediation: e.remediation,
  };
  return {
    content: [{ type: "text", text: JSON.stringify({ error }, null, 2) }],
    structuredContent: { error },
    isError: true,
    // Backend stderr can echo evidence bytes.
    _meta: provenance(source ?? (e.category === "backend" ? "backend" : false)),
  };
}
