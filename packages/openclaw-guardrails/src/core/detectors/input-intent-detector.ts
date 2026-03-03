import { hasPatternMatch } from "../../redaction/redact.js";
import { REASON_CODES } from "../reason-codes.js";
import { safeStringify, truncate } from "../event-utils.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

export function detectInputIntent(context: DetectorContext): RuleHit[] {
  const { event, config } = context;
  const hits: RuleHit[] = [];

  const content = event.content ?? "";
  const argsSerialized = safeStringify(event.args);

  if (content.length > config.limits.maxInputChars) {
    hits.push({
      ruleId: "limit.input.content",
      reasonCode: REASON_CODES.INPUT_LIMIT_EXCEEDED,
      decision: "DENY",
      weight: 0.75
    });
  }

  if (argsSerialized.length > config.limits.maxToolArgChars) {
    hits.push({
      ruleId: "limit.tool.args",
      reasonCode: REASON_CODES.INPUT_LIMIT_EXCEEDED,
      decision: "DENY",
      weight: 0.75
    });
  }

  if (
    event.phase === "tool_result_persist" &&
    content.length > config.limits.maxOutputChars
  ) {
    hits.push({
      ruleId: "limit.output.content",
      reasonCode: REASON_CODES.INPUT_LIMIT_EXCEEDED,
      decision: "DENY",
      weight: 0.75
    });
  }

  if (event.content) {
    event.content = truncate(event.content, config.limits.maxOutputChars);
  }

  const text = `${event.content ?? ""}\n${argsSerialized}`;
  if (hasPatternMatch(text, config.deny.promptInjectionPatterns)) {
    hits.push({
      ruleId: "prompt.injection.pattern",
      reasonCode: REASON_CODES.PROMPT_INJECTION,
      decision: "DENY",
      weight: 0.95
    });
  }

  if (hasPatternMatch(text, config.deny.exfiltrationPatterns)) {
    hits.push({
      ruleId: "exfiltration.pattern",
      reasonCode: REASON_CODES.EXFIL_PATTERN,
      decision: "DENY",
      weight: 0.85
    });
  }

  return hits;
}
