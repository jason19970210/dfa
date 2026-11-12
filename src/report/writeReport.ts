import { closeSync, constants, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import { join } from "node:path";
import { reportDir } from "../config.js";

const SAFE_NAME = /^[A-Za-z0-9._-]+\.html$/;

/** Map an agent-supplied report name to a path inside the dfa report directory. */
export function reportPathForName(name: string): string {
  if (!SAFE_NAME.test(name) || name.includes("..")) {
    throw new Error(`report_name_invalid: report name must be a plain file name ending in .html: ${JSON.stringify(name)}`);
  }
  const dir = reportDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // ponytail: checks the last component only; an ancestor swapped between this
  // check and the open is a residual race (P2 can open the dir fd and use openat).
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error(`report_dir_unsafe: report directory is a symlink or not a directory: ${dir}`);
  }
  return join(dir, name);
}

/**
 * Create a new report file; never overwrite and never follow a symlink.
 * O_EXCL fails on any existing path (file, hardlink or symlink), which keeps
 * reports from ever replacing evidence or the custody log.
 */
export function writeReportExclusive(path: string, html: string): void {
  let fd: number;
  try {
    fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "ELOOP") {
      throw new Error(`report_exists: refusing to overwrite existing path: ${path}`);
    }
    throw err;
  }
  try {
    writeSync(fd, html);
  } finally {
    closeSync(fd);
  }
}
