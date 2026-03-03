import { hasPatternMatch } from "../../redaction/redact.js";
import {
  canonicalizePathCandidate,
  canonicalizeRoots,
  isCanonicalPathWithinRoots
} from "../path-canonical.js";
import { collectPathCandidates, unique } from "../event-utils.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

export async function detectPathCanonical(context: DetectorContext): Promise<RuleHit[]> {
  const { event, config } = context;

  if (event.phase !== "before_tool_call") {
    return [];
  }

  const hits: RuleHit[] = [];
  const candidates = collectPathCandidates(event.args);

  if (candidates.length === 0) {
    return hits;
  }

  const roots = unique([config.workspaceRoot, ...config.allow.writablePaths]);
  const canonicalRoots = await canonicalizeRoots(roots);

  for (const candidate of candidates) {
    if (hasPatternMatch(candidate, config.deny.pathPatterns)) {
      hits.push({
        ruleId: "path.traversal.pattern",
        reasonCode: REASON_CODES.PATH_TRAVERSAL,
        decision: "DENY",
        weight: 0.95
      });
    }

    const checked = await canonicalizePathCandidate(candidate, config.workspaceRoot);

    if (
      config.pathPolicy.enforceCanonicalRealpath &&
      !isCanonicalPathWithinRoots(checked.canonicalPath, canonicalRoots)
    ) {
      hits.push({
        ruleId: "path.workspace.boundary",
        reasonCode: REASON_CODES.PATH_OUTSIDE_WORKSPACE,
        decision: "DENY",
        weight: 0.9
      });
    }

    if (config.pathPolicy.denySymlinkTraversal && checked.traversedSymlink) {
      hits.push({
        ruleId: "path.symlink.traversal",
        reasonCode: REASON_CODES.PATH_SYMLINK_TRAVERSAL,
        decision: "DENY",
        weight: 0.9
      });
    }
  }

  return hits;
}
