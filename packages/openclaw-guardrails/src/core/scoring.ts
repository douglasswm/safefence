import type { RuleHit } from "./types.js";

const DECISION_MULTIPLIER: Record<RuleHit["decision"], number> = {
  DENY: 1,
  REDACT: 0.6
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function aggregateRisk(hits: RuleHit[]): number {
  if (hits.length === 0) {
    return 0;
  }

  const weighted = hits.reduce((acc, hit) => {
    const multiplier = DECISION_MULTIPLIER[hit.decision] ?? 0.5;
    return acc + clamp(hit.weight, 0, 1) * multiplier;
  }, 0);

  const normalized = 1 - Math.exp(-weighted);
  return Number(clamp(normalized, 0, 1).toFixed(4));
}
