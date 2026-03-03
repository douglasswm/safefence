export type BudgetKind = "request" | "toolCall";

interface AgentBudget {
  requests: number[];
  toolCalls: number[];
}

export class BudgetStore {
  private readonly perKey = new Map<string, AgentBudget>();

  checkAndRecord(
    subjectKey: string,
    kind: BudgetKind,
    limitPerMinute: number,
    nowMs = Date.now()
  ): boolean {
    if (limitPerMinute <= 0) {
      return true;
    }

    const budget = this.getOrCreateAgentBudget(subjectKey);
    const bucket = kind === "request" ? budget.requests : budget.toolCalls;

    const windowStart = nowMs - 60_000;
    while (bucket.length > 0 && bucket[0] < windowStart) {
      bucket.shift();
    }

    bucket.push(nowMs);
    return bucket.length > limitPerMinute;
  }

  private getOrCreateAgentBudget(subjectKey: string): AgentBudget {
    const current = this.perKey.get(subjectKey);
    if (current) {
      return current;
    }

    const created: AgentBudget = {
      requests: [],
      toolCalls: []
    };

    this.perKey.set(subjectKey, created);
    return created;
  }
}
