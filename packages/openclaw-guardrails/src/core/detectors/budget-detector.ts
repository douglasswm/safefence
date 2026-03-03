import { BudgetStore } from "../budget-store.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

function toBudgetKey(context: DetectorContext): string {
  const { event, config } = context;
  if (config.tenancy.budgetKeyMode === "agent") {
    return event.agentId;
  }

  const principal = event.metadata.principal;
  const conversationId = principal?.conversationId ?? "unknown-conversation";
  const senderId = principal?.senderId ?? "unknown-sender";
  return `${event.agentId}|${conversationId}|${senderId}`;
}

export function detectBudget(
  context: DetectorContext,
  budgetStore: BudgetStore
): RuleHit[] {
  const { event, config } = context;
  const hits: RuleHit[] = [];
  const budgetKey = toBudgetKey(context);

  if (
    budgetStore.checkAndRecord(
      budgetKey,
      "request",
      config.limits.maxRequestsPerMinute
    )
  ) {
    hits.push({
      ruleId: "budget.requests",
      reasonCode: REASON_CODES.BUDGET_REQUEST_EXCEEDED,
      decision: "DENY",
      weight: 0.65
    });
  }

  if (
    event.phase === "before_tool_call" &&
    budgetStore.checkAndRecord(
      budgetKey,
      "toolCall",
      config.limits.maxToolCallsPerMinute
    )
  ) {
    hits.push({
      ruleId: "budget.tool_calls",
      reasonCode: REASON_CODES.BUDGET_TOOL_CALL_EXCEEDED,
      decision: "DENY",
      weight: 0.75
    });
  }

  return hits;
}
