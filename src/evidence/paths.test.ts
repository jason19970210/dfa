import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveEvidencePath } from "./paths.js";

function layout() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "dfa-paths-")));
  const root = join(base, "evidence");
  const outside = join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  writeFileSync(join(root, "mem.img"), "x");
  writeFileSync(join(outside, "secret.img"), "y");
  return { root, outside };
}

describe("resolveEvidencePath", () => {
  it("returns the realpath of a regular file", () => {
    const { root } = layout();
    expect(resolveEvidencePath(join(root, ".", "mem.img"), root)).toBe(join(root, "mem.img"));
  });

  it("rejects a missing path", () => {
    const { root } = layout();
    expect(() => resolveEvidencePath(join(root, "nope.img"), root)).toThrow(/^evidence_not_found/);
  });

  it("rejects a directory", () => {
    const { root } = layout();
    expect(() => resolveEvidencePath(root, root)).toThrow(/^evidence_not_regular_file/);
  });

  it("rejects an in-root symlink that escapes the root", () => {
    const { root, outside } = layout();
    symlinkSync(join(outside, "secret.img"), join(root, "link.img"));
    expect(() => resolveEvidencePath(join(root, "link.img"), root)).toThrow(/^evidence_outside_root/);
  });

  it("follows an in-root symlink to an in-root file", () => {
    const { root } = layout();
    symlinkSync(join(root, "mem.img"), join(root, "alias.img"));
    expect(resolveEvidencePath(join(root, "alias.img"), root)).toBe(join(root, "mem.img"));
  });

  it("allows any regular file when no root is set", () => {
    const { outside } = layout();
    expect(resolveEvidencePath(join(outside, "secret.img"), undefined)).toBe(join(outside, "secret.img"));
  });
});
