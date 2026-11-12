import { realpathSync, statSync } from "node:fs";
import { sep } from "node:path";

/**
 * Resolve an evidence path to the realpath of a regular file.
 *
 * Containment is checked on realpaths, so a symlink inside the evidence root
 * that points outside it is refused. When no root is configured
 * (DFA_EVIDENCE_DIR unset) any regular file is accepted.
 *
 * ponytail: the file can still be swapped between this check and the backend
 * opening it (TOCTOU); P2 registration re-checks identity before and after.
 */
export function resolveEvidencePath(
  input: string,
  evidenceDir: string | undefined = process.env.DFA_EVIDENCE_DIR,
): string {
  let real: string;
  try {
    real = realpathSync(input);
  } catch {
    throw new Error(`evidence_not_found: memory image not found: ${input}`);
  }
  if (!statSync(real).isFile()) {
    throw new Error(`evidence_not_regular_file: not a regular file: ${input}`);
  }
  if (evidenceDir) {
    const root = realpathSync(evidenceDir);
    if (real !== root && !real.startsWith(root + sep)) {
      throw new Error(`evidence_outside_root: image resolves outside DFA_EVIDENCE_DIR (${root}): ${input}`);
    }
  }
  return real;
}
