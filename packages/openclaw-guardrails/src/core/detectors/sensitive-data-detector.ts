import { redactWithPatterns, hasPatternMatch } from "../../redaction/redact.js";
import { collectStrings } from "../event-utils.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext, DetectorResult } from "./types.js";

export function detectSensitiveData(context: DetectorContext): DetectorResult {
  const { event, config } = context;
  const hits: RuleHit[] = [];

  const originalContent = event.content ?? "";
  let working = originalContent;

  if (working) {
    const secretScan = redactWithPatterns(
      working,
      config.redaction.secretPatterns,
      config.redaction.replacement
    );
    working = secretScan.redacted;

    if (secretScan.matches.length > 0) {
      hits.push({
        ruleId: "redaction.secrets",
        reasonCode: REASON_CODES.SECRET_DETECTED,
        decision: "REDACT",
        weight: 0.7
      });
    }

    const piiScan = redactWithPatterns(
      working,
      config.redaction.piiPatterns,
      config.redaction.replacement
    );
    working = piiScan.redacted;

    if (piiScan.matches.length > 0) {
      hits.push({
        ruleId: "redaction.pii",
        reasonCode: REASON_CODES.PII_DETECTED,
        decision: "REDACT",
        weight: 0.5
      });
    }
  }

  const argsText = collectStrings(event.args).join("\n");
  if (hasPatternMatch(argsText, config.redaction.secretPatterns)) {
    hits.push({
      ruleId: "redaction.secrets.args",
      reasonCode: REASON_CODES.SECRET_DETECTED,
      decision: "REDACT",
      weight: 0.7
    });
  }

  if (hasPatternMatch(argsText, config.redaction.piiPatterns)) {
    hits.push({
      ruleId: "redaction.pii.args",
      reasonCode: REASON_CODES.PII_DETECTED,
      decision: "REDACT",
      weight: 0.5
    });
  }

  if (originalContent && working !== originalContent) {
    return {
      hits,
      redactedContent: working
    };
  }

  return { hits };
}
