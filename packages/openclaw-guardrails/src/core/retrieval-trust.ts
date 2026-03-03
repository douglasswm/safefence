import { REASON_CODES } from "./reason-codes.js";
import type { GuardrailsConfig, NormalizedEvent, RuleHit } from "./types.js";

const HIGH_RISK_TOOLS = new Set([
  "exec",
  "process",
  "write",
  "edit",
  "apply_patch",
  "skills.install"
]);

function trustRank(level: "low" | "medium" | "high" | undefined): number {
  switch (level) {
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

export function detectRetrievalTrust(
  event: NormalizedEvent,
  config: GuardrailsConfig
): RuleHit[] {
  if (event.phase !== "before_tool_call") {
    return [];
  }

  if (!config.retrievalTrust?.requiredForToolExecution) {
    return [];
  }

  if (!event.toolName || !HIGH_RISK_TOOLS.has(event.toolName)) {
    return [];
  }

  if (event.metadata.sourceType !== "retrieval") {
    return [];
  }

  const hits: RuleHit[] = [];

  const trustLevel = event.metadata.trustLevel;
  if (!trustLevel) {
    hits.push({
      ruleId: "retrieval.trust.required",
      reasonCode: REASON_CODES.RETRIEVAL_TRUST_REQUIRED,
      decision: "DENY",
      weight: 0.7
    });
    return hits;
  }

  const minimumRank = trustRank(config.retrievalTrust.minimumTrustLevel);
  if (trustRank(trustLevel) < minimumRank) {
    hits.push({
      ruleId: "retrieval.trust.level",
      reasonCode: REASON_CODES.RETRIEVAL_TRUST_LEVEL_TOO_LOW,
      decision: "DENY",
      weight: 0.75
    });
  }

  if (
    config.retrievalTrust.requireSignedSource &&
    event.metadata.sourceSignatureValid !== true
  ) {
    hits.push({
      ruleId: "retrieval.trust.signature",
      reasonCode: REASON_CODES.RETRIEVAL_SIGNATURE_INVALID,
      decision: "DENY",
      weight: 0.8
    });
  }

  return hits;
}
