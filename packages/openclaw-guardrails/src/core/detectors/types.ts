import type { GuardrailsConfig, NormalizedEvent, RuleHit } from "../types.js";

export interface DetectorResult {
  hits: RuleHit[];
  redactedContent?: string;
}

export interface DetectorContext {
  event: NormalizedEvent;
  config: GuardrailsConfig;
}
