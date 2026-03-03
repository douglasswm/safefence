import fs from "node:fs/promises";
import path from "node:path";

export interface PathCheckResult {
  resolvedPath: string;
  canonicalPath: string;
  traversedSymlink: boolean;
  exists: boolean;
}

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await fs.lstat(candidate);
    return true;
  } catch {
    return false;
  }
}

async function nearestExistingParent(target: string): Promise<string> {
  let current = target;

  while (true) {
    if (await pathExists(current)) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return current;
    }

    current = parent;
  }
}

export async function canonicalizeRoots(roots: string[]): Promise<string[]> {
  const canonicalRoots: string[] = [];

  for (const root of roots) {
    const resolved = path.resolve(root);
    if (await pathExists(resolved)) {
      canonicalRoots.push(await fs.realpath(resolved));
      continue;
    }

    canonicalRoots.push(resolved);
  }

  return Array.from(new Set(canonicalRoots.map((value) => path.normalize(value))));
}

export async function canonicalizePathCandidate(
  candidate: string,
  workspaceRoot: string
): Promise<PathCheckResult> {
  const resolvedPath = path.isAbsolute(candidate)
    ? path.normalize(candidate)
    : path.resolve(workspaceRoot, candidate);

  const exists = await pathExists(resolvedPath);

  if (exists) {
    const canonicalPath = path.normalize(await fs.realpath(resolvedPath));
    return {
      resolvedPath,
      canonicalPath,
      traversedSymlink: canonicalPath !== resolvedPath,
      exists: true
    };
  }

  const parent = await nearestExistingParent(path.dirname(resolvedPath));
  const canonicalParent = path.normalize(await fs.realpath(parent));
  const relativeFromParent = path.relative(parent, resolvedPath);
  const canonicalPath = path.normalize(path.resolve(canonicalParent, relativeFromParent));

  return {
    resolvedPath,
    canonicalPath,
    traversedSymlink: path.normalize(parent) !== canonicalParent,
    exists: false
  };
}

export function isCanonicalPathWithinRoots(
  canonicalPath: string,
  canonicalRoots: string[]
): boolean {
  const normalizedCandidate = path.normalize(canonicalPath);

  return canonicalRoots.some((root) => {
    const normalizedRoot = path.normalize(root);
    return (
      normalizedCandidate === normalizedRoot ||
      normalizedCandidate.startsWith(`${normalizedRoot}${path.sep}`)
    );
  });
}
