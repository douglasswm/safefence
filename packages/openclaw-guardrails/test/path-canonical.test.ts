import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  canonicalizePathCandidate,
  canonicalizeRoots,
  isCanonicalPathWithinRoots
} from "../src/core/path-canonical.js";

describe("path canonical", () => {
  it("detects symlink traversal for existing paths", async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "path-canonical-"));
    const workspace = path.join(tempRoot, "workspace");
    const outside = path.join(tempRoot, "outside");
    const link = path.join(workspace, "link");

    await fs.mkdir(workspace, { recursive: true });
    await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, "secrets.txt"), "secret", "utf8");
    await fs.symlink(path.join(outside, "secrets.txt"), link);

    const roots = await canonicalizeRoots([workspace]);
    const checked = await canonicalizePathCandidate(link, workspace);

    expect(checked.traversedSymlink).toBe(true);
    expect(isCanonicalPathWithinRoots(checked.canonicalPath, roots)).toBe(false);
  });
});
