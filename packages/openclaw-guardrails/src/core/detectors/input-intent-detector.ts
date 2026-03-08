import { hasPatternMatch } from "../../redaction/redact.js";
import { REASON_CODES } from "../reason-codes.js";
import { safeStringify, truncate } from "../event-utils.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

// Pre-compiled with bounded quantifiers to prevent ReDoS
const CONTEXT_PROBE_REGEXES: RegExp[] = [
  /list.{0,80}(?:your|the).{0,80}files/i,
  /what.{0,80}files.{0,80}(?:do you|are|have)/i,
  /show.{0,80}(?:your|the).{0,80}(?:workspace|directory|folder|context)/i,
  /what(?:'s| is).{0,80}(?:in )?your.{0,80}(?:workspace|directory|folder|context)/i,
  /(?:print|show|read|output|display|reveal|dump|give).{0,80}\b(?:agents|soul|bootstrap|identity|heartbeat|tools|user)\.md\b/i,
  /(?:what|which).{0,80}(?:md|markdown).{0,80}files/i
];

function detectContextProbe(
  text: string,
  context: DetectorContext
): RuleHit | null {
  const { config } = context;

  if (!config.outboundGuard.enabled) {
    return null;
  }

  const lower = text.toLowerCase();

  // Check if message references injected file names directly
  const fileNames = config.outboundGuard.injectedFileNames;
  const mentionsInjectedFile = fileNames.some((f) => lower.includes(f.toLowerCase()));

  if (mentionsInjectedFile) {
    return {
      ruleId: "input.context_probe.file_reference",
      reasonCode: REASON_CODES.SYSTEM_PROMPT_LEAK,
      decision: "DENY",
      weight: 0.9
    };
  }

  // Check for workspace/context probing patterns (pre-compiled, bounded quantifiers)
  const hasProbePattern = CONTEXT_PROBE_REGEXES.some((regex) => regex.test(lower));

  if (hasProbePattern) {
    return {
      ruleId: "input.context_probe.pattern",
      reasonCode: REASON_CODES.SYSTEM_PROMPT_LEAK,
      decision: "DENY",
      weight: 0.85
    };
  }

  return null;
}

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

  // Detect requests probing for injected context / file names
  if (event.phase === "message_received") {
    const probeHit = detectContextProbe(text, context);
    if (probeHit) {
      hits.push(probeHit);
    }
  }

  return hits;
}
