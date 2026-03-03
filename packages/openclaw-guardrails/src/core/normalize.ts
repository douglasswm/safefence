import { asMetadata, asRecord } from "./event-utils.js";
import type { GuardEvent, NormalizedEvent, Phase } from "./types.js";

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function pickContent(input: Record<string, unknown>): string | undefined {
  return (
    asString(input.content) ??
    asString(input.message) ??
    asString(input.output) ??
    asString(input.prompt) ??
    asString(input.text)
  );
}

function pickToolName(input: Record<string, unknown>): string | undefined {
  const direct = asString(input.toolName);
  if (direct) {
    return direct;
  }

  const tool = asRecord(input.tool);
  return asString(tool.name);
}

function pickArgs(input: Record<string, unknown>): Record<string, unknown> {
  const direct = asRecord(input.args);
  if (Object.keys(direct).length > 0) {
    return direct;
  }

  return asRecord(input.toolArgs);
}

function pickPhase(input: Record<string, unknown>, fallback: Phase): Phase {
  const phase = asString(input.phase);
  switch (phase) {
    case "before_agent_start":
    case "message_received":
    case "before_tool_call":
    case "tool_result_persist":
    case "agent_end":
      return phase;
    default:
      return fallback;
  }
}

export function normalizeGuardEvent(
  raw: Partial<GuardEvent> & Record<string, unknown>,
  fallbackPhase: Phase
): NormalizedEvent {
  const input = asRecord(raw);
  const phase = pickPhase(input, fallbackPhase);
  const agentId = asString(input.agentId) ?? "unknown-agent";

  const metadata = asMetadata(input.metadata);
  const args = pickArgs(input);

  return {
    phase,
    agentId,
    toolName: pickToolName(input),
    content: pickContent(input),
    args,
    metadata
  };
}
