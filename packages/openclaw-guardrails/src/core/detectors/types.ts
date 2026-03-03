import type {
  GuardDecision,
  GuardrailsConfig,
  NormalizedEvent,
  PrincipalContext,
  RuleHit
} from "../types.js";

export interface ApprovalRequirement {
  reason: string;
  requiredRole: "owner" | "admin";
}

export interface DetectorResult {
  hits: RuleHit[];
  redactedContent?: string;
}

export interface PrincipalAuthzResult extends DetectorResult {
  principal?: PrincipalContext;
  approvalRequirement?: ApprovalRequirement;
}

export interface OwnerApprovalResult extends DetectorResult {
  approvalChallenge?: GuardDecision["approvalChallenge"];
}

export interface DetectorContext {
  event: NormalizedEvent;
  config: GuardrailsConfig;
}
