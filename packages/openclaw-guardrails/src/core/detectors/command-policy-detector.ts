import { hasPatternMatch } from "../../redaction/redact.js";
import { extractCommandFromArgs, parseCommand } from "../command-parse.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

export function detectCommandPolicy(context: DetectorContext): RuleHit[] {
  const { event, config } = context;

  if (event.phase !== "before_tool_call") {
    return [];
  }

  const hits: RuleHit[] = [];

  if (
    event.toolName &&
    config.allow.tools.length > 0 &&
    !config.allow.tools.includes(event.toolName)
  ) {
    hits.push({
      ruleId: "tool.allowlist",
      reasonCode: REASON_CODES.TOOL_NOT_ALLOWED,
      decision: "DENY",
      weight: 0.9
    });
  }

  const command = extractCommandFromArgs(event.args);
  if (!command) {
    return hits;
  }

  const parsed = parseCommand(command, config.deny.shellOperatorPatterns);
  event.metadata.parsedCommand = parsed;

  const allowedBinary = config.allow.commands.find(
    (entry) => entry.binary === parsed.binary
  );

  if (!allowedBinary) {
    hits.push({
      ruleId: "command.binary.allowlist",
      reasonCode: REASON_CODES.COMMAND_BINARY_NOT_ALLOWED,
      decision: "DENY",
      weight: 0.85
    });
  }

  if (parsed.hasShellOperators && !allowedBinary?.allowShellOperators) {
    hits.push({
      ruleId: "command.shell_operators",
      reasonCode: REASON_CODES.COMMAND_SHELL_OPERATOR_BLOCKED,
      decision: "DENY",
      weight: 0.95
    });
  }

  if (allowedBinary?.argPattern) {
    try {
      const regex = new RegExp(allowedBinary.argPattern, "u");
      if (!regex.test(parsed.args.trim())) {
        hits.push({
          ruleId: "command.args.pattern",
          reasonCode: REASON_CODES.COMMAND_ARG_PATTERN_BLOCKED,
          decision: "DENY",
          weight: 0.8
        });
      }
    } catch {
      // Malformed pattern — fail closed to prevent bypass.
      hits.push({
        ruleId: "command.args.pattern.invalid",
        reasonCode: REASON_CODES.COMMAND_ARG_PATTERN_BLOCKED,
        decision: "DENY",
        weight: 0.9
      });
    }
  }

  if (hasPatternMatch(parsed.raw, config.deny.commandPatterns)) {
    hits.push({
      ruleId: "command.destructive.pattern",
      reasonCode: REASON_CODES.DESTRUCTIVE_COMMAND,
      decision: "DENY",
      weight: 1
    });
  }

  return hits;
}
