export type Phase =
  | "before_agent_start"
  | "message_received"
  | "before_tool_call"
  | "tool_result_persist"
  | "agent_end";

export type Decision = "ALLOW" | "REDACT" | "DENY";

export interface AllowedCommand {
  binary: string;
  argPattern?: string;
  allowShellOperators?: boolean;
}

export interface GuardMetadata extends Record<string, unknown> {
  sourceType?: "user" | "retrieval" | "tool";
  sourceId?: string;
  trustLevel?: "low" | "medium" | "high";
  sourceSignatureValid?: boolean;
}

export interface GuardrailsConfig {
  mode: "enforce" | "audit";
  failClosed: boolean;
  workspaceRoot: string;
  allow: {
    tools: string[];
    commands: AllowedCommand[];
    writablePaths: string[];
    networkHosts: string[];
    allowPrivateEgress: boolean;
  };
  deny: {
    commandPatterns: string[];
    pathPatterns: string[];
    promptInjectionPatterns: string[];
    exfiltrationPatterns: string[];
    shellOperatorPatterns: string[];
  };
  redaction: {
    secretPatterns: string[];
    piiPatterns: string[];
    replacement: string;
    applyInAuditMode: boolean;
  };
  limits: {
    maxInputChars: number;
    maxToolArgChars: number;
    maxOutputChars: number;
    maxRequestsPerMinute: number;
    maxToolCallsPerMinute: number;
  };
  pathPolicy: {
    enforceCanonicalRealpath: boolean;
    denySymlinkTraversal: boolean;
  };
  supplyChain: {
    trustedSkillSources: string[];
    requireSkillHash: boolean;
    allowedSkillHashes: string[];
  };
  retrievalTrust?: {
    requiredForToolExecution: boolean;
    minimumTrustLevel: "high" | "medium";
    requireSignedSource: boolean;
  };
}

export interface GuardEvent {
  phase: Phase;
  agentId: string;
  toolName?: string;
  content?: string;
  args?: Record<string, unknown>;
  metadata?: GuardMetadata;
}

export interface GuardDecision {
  decision: Decision;
  reasonCodes: string[];
  riskScore: number;
  redactedContent?: string;
  telemetry: {
    matchedRules: string[];
    elapsedMs: number;
  };
}

export interface RuleHit {
  ruleId: string;
  reasonCode: string;
  decision: Exclude<Decision, "ALLOW">;
  weight: number;
}

export interface NormalizedEvent extends GuardEvent {
  args: Record<string, unknown>;
  metadata: GuardMetadata;
}
