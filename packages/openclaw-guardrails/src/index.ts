export { GuardrailsEngine } from "./core/engine.js";
export { REASON_CODES } from "./core/reason-codes.js";
export type {
  ApproverRole,
  ChannelType,
  DataClass,
  Decision,
  PrincipalContext,
  PrincipalRole,
  RolloutStage,
  GuardDecision,
  GuardEvent,
  GuardrailsConfig,
  Phase
} from "./core/types.js";
export { UNKNOWN_SENDER, UNKNOWN_CONVERSATION } from "./core/identity.js";
export { createDefaultConfig, mergeConfig } from "./rules/default-policy.js";
export { createOpenClawGuardrailsPlugin } from "./plugin/openclaw-adapter.js";
export { registerOpenClawGuardrails } from "./plugin/openclaw-extension.js";
