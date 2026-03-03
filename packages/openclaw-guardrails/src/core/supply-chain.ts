import { canonicalizePathCandidate, canonicalizeRoots, isCanonicalPathWithinRoots } from "./path-canonical.js";
import { REASON_CODES } from "./reason-codes.js";
import type { GuardrailsConfig, NormalizedEvent, RuleHit } from "./types.js";

function pickString(args: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }

  return undefined;
}

function isRemoteSource(source: string): boolean {
  return /^(?:https?:\/\/|git@|ssh:\/\/)/iu.test(source) || source.includes("github.com/");
}

function isTrustedSource(source: string, trustedSources: string[]): boolean {
  const normalized = source.toLowerCase();

  return trustedSources.some((trusted) => normalized.startsWith(trusted.toLowerCase()));
}

export async function detectSupplyChainRisk(
  event: NormalizedEvent,
  config: GuardrailsConfig
): Promise<RuleHit[]> {
  if (event.phase !== "before_tool_call" || event.toolName !== "skills.install") {
    return [];
  }

  const hits: RuleHit[] = [];
  const source = pickString(event.args, ["source", "repo", "repository", "url", "skillSource"]);

  if (!source || !isTrustedSource(source, config.supplyChain.trustedSkillSources)) {
    hits.push({
      ruleId: "supply_chain.untrusted_source",
      reasonCode: REASON_CODES.SUPPLY_CHAIN_UNTRUSTED_SOURCE,
      decision: "DENY",
      weight: 0.85
    });
  }

  const hash = pickString(event.args, ["hash", "sha256", "digest"]);
  if (source && isRemoteSource(source) && config.supplyChain.requireSkillHash && !hash) {
    hits.push({
      ruleId: "supply_chain.hash.required",
      reasonCode: REASON_CODES.SUPPLY_CHAIN_HASH_REQUIRED,
      decision: "DENY",
      weight: 0.8
    });
  }

  if (
    hash &&
    config.supplyChain.allowedSkillHashes.length > 0 &&
    !config.supplyChain.allowedSkillHashes.includes(hash)
  ) {
    hits.push({
      ruleId: "supply_chain.hash.allowlist",
      reasonCode: REASON_CODES.SUPPLY_CHAIN_HASH_BLOCKED,
      decision: "DENY",
      weight: 0.8
    });
  }

  const targetDir = pickString(event.args, ["targetDir", "path", "installDir"]);
  if (targetDir) {
    const canonicalRoots = await canonicalizeRoots([
      config.workspaceRoot,
      ...config.allow.writablePaths
    ]);
    const checked = await canonicalizePathCandidate(targetDir, config.workspaceRoot);

    if (
      config.pathPolicy.enforceCanonicalRealpath &&
      !isCanonicalPathWithinRoots(checked.canonicalPath, canonicalRoots)
    ) {
      hits.push({
        ruleId: "supply_chain.target_dir.outside_workspace",
        reasonCode: REASON_CODES.PATH_OUTSIDE_WORKSPACE,
        decision: "DENY",
        weight: 0.9
      });
    }

    if (config.pathPolicy.denySymlinkTraversal && checked.traversedSymlink) {
      hits.push({
        ruleId: "supply_chain.target_dir.symlink_traversal",
        reasonCode: REASON_CODES.PATH_SYMLINK_TRAVERSAL,
        decision: "DENY",
        weight: 0.9
      });
    }
  }

  return hits;
}
