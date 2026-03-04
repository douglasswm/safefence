import { redactWithPatterns } from "../../redaction/redact.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext, DetectorResult } from "./types.js";

function detectSystemPromptLeak(
  content: string,
  context: DetectorContext
): DetectorResult {
  const { config } = context;

  if (!config.outboundGuard.enabled) {
    return { hits: [] };
  }

  const lower = content.toLowerCase();

  const leakPatterns = config.outboundGuard.systemPromptLeakPatterns;
  const fileNames = config.outboundGuard.injectedFileNames;

  const hasLeakPattern = leakPatterns.some((p) => lower.includes(p.toLowerCase()));
  const hasFileName = fileNames.some((f) => lower.includes(f.toLowerCase()));

  if (!hasLeakPattern && !hasFileName) {
    return { hits: [] };
  }

  return {
    hits: [
      {
        ruleId: "output.system_prompt_leak",
        reasonCode: REASON_CODES.SYSTEM_PROMPT_LEAK,
        decision: "DENY",
        weight: 0.95
      }
    ]
  };
}

export function detectOutputSafety(
  context: DetectorContext,
  preRedactedContent?: string
): DetectorResult {
  const { event, config } = context;

  if (
    event.phase !== "tool_result_persist" &&
    event.phase !== "message_received" &&
    event.phase !== "message_sending"
  ) {
    return { hits: [] };
  }

  const content = preRedactedContent ?? event.content ?? "";
  if (!content) {
    return { hits: [] };
  }

  // For message_sending phase, check system prompt leak patterns
  if (event.phase === "message_sending") {
    return detectSystemPromptLeak(content, context);
  }

  // Existing tool_result_persist / message_received sanitization
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
