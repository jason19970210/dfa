export type ErrorCategory = "input" | "evidence" | "backend" | "config" | "internal";

export class DfaError extends Error {
  constructor(
    readonly code: string,
    readonly category: ErrorCategory,
    message: string,
    readonly retryable = false,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "DfaError";
  }
}

const KNOWN: Record<string, { category: ErrorCategory; retryable: boolean; remediation?: string }> = {
  evidence_not_found: { category: "evidence", retryable: false, remediation: "Pass the absolute path of an existing image file." },
  evidence_not_regular_file: { category: "evidence", retryable: false, remediation: "Pass a regular file, not a directory or device." },
  evidence_outside_root: { category: "evidence", retryable: false, remediation: "Move the image under DFA_EVIDENCE_DIR or ask the examiner to change it." },
  backend_timeout: { category: "backend", retryable: true, remediation: "Retry once; if it times out again, narrow the plugin (e.g. --pid)." },
  backend_aborted: { category: "backend", retryable: true },
  backend_output_too_large: { category: "backend", retryable: false, remediation: "Narrow the query (e.g. --pid)." },
  backend_failed: { category: "backend", retryable: false, remediation: "Check the profile with the info tool and that symbols are provisioned (DFA_SYMBOL_DIRS)." },
  backend_malformed_output: { category: "backend", retryable: false, remediation: "Treat as no result; do not report zero findings." },
  custody_corrupt: { category: "internal", retryable: false, remediation: "Preserve the custody log as-is and investigate; do not rely on prior results." },
  report_name_invalid: { category: "input", retryable: false, remediation: "Use a plain file name ending in .html." },
  report_dir_unsafe: { category: "config", retryable: false, remediation: "Point DFA_REPORT_DIR (or DFA_HOME/reports) at a real directory, not a symlink." },
  report_exists: { category: "input", retryable: false, remediation: "Choose a new report name; dfa never overwrites files." },
};

/** Map any thrown value to a DfaError; Errors whose message starts with "<code>: " keep that code. */
export function toDfaError(err: unknown): DfaError {
  if (err instanceof DfaError) return err;
  const message = err instanceof Error ? err.message : String(err);
  const m = /^([a-z_]+): ([\s\S]*)$/.exec(message);
  const known = m ? KNOWN[m[1]] : undefined;
  if (m && known) return new DfaError(m[1], known.category, m[2], known.retryable, known.remediation);
  return new DfaError("internal_error", "internal", message);
}
