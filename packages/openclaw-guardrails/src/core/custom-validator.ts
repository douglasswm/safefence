import type { Phase, RuleHit, NormalizedEvent, GuardrailsConfig } from "./types.js";

export interface CustomValidatorContext {
  event: NormalizedEvent;
  config: GuardrailsConfig;
}

export interface CustomValidator {
  id: string;
  phases: Phase[];
  validate(context: CustomValidatorContext): RuleHit[] | Promise<RuleHit[]>;
}
