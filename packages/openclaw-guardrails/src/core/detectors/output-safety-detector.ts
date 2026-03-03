import { redactWithPatterns } from "../../redaction/redact.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext, DetectorResult } from "./types.js";

export function detectOutputSafety(
  context: DetectorContext,
  preRedactedContent?: string
): DetectorResult {
  const { event, config } = context;

  if (event.phase !== "tool_result_persist" && event.phase !== "message_received") {
    return { hits: [] };
  }

  const content = preRedactedContent ?? event.content ?? "";
  if (!content) {
    return { hits: [] };
  }

  const suspiciousPatterns = [
    "<script",
    "begin system prompt",
    "developer message",
    "token=",
    "authorization: bearer"
  ];

  const shouldSanitize = suspiciousPatterns.some((pattern) =>
    content.toLowerCase().includes(pattern)
  );

  if (!shouldSanitize) {
    return { hits: [] };
  }

  const sanitized = redactWithPatterns(
    content,
    ["token=[^\\s&]+", "authorization:\\s*bearer\\s+[^\\s]+", "<script[^>]*>"],
    config.redaction.replacement
  ).redacted;

  const hits: RuleHit[] = [
    {
      ruleId: "output.untrusted.handling",
      reasonCode: REASON_CODES.UNTRUSTED_OUTPUT,
      decision: "REDACT",
      weight: 0.55
    }
  ];

  return {
    hits,
    redactedContent: sanitized
  };
}
