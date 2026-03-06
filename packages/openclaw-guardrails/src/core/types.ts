export type Phase =
  | "before_agent_start"
  | "message_received"
  | "before_tool_call"
  | "tool_result_persist"
  | "message_sending"
  | "agent_end";

export type Decision = "ALLOW" | "REDACT" | "DENY";
export type PrincipalRole = "owner" | "admin" | "member" | "unknown";
export type ApproverRole = Extract<PrincipalRole, "owner" | "admin">;
export type ChannelType = "dm" | "group" | "thread" | "unknown";
export type DataClass = "public" | "internal" | "restricted" | "secret";

export interface AllowedCommand {
  binary: string;
  argPattern?: string;
  allowShellOperators?: boolean;
}

export interface PrincipalContext {
  senderId: string;
  senderHandle?: string;
  role: PrincipalRole;
  channelId?: string;
  conversationId: string;
  channelType: ChannelType;
  mentionedAgent?: boolean;
  pairedDevice?: boolean;
}

export interface ApprovalContext {
  token?: string;
  requestId?: string;
}

export type RolloutStage =
  | "stage_a_audit"
  | "stage_b_high_risk_enforce"
  | "stage_c_full_enforce";

export interface GuardMetadata extends Record<string, unknown> {
  sourceType?: "user" | "retrieval" | "tool";
  sourceId?: string;
  trustLevel?: "low" | "medium" | "high";
  sourceSignatureValid?: boolean;
  principal?: PrincipalContext;
  approval?: ApprovalContext;
  dataClass?: DataClass;
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
  principal: {
    requireContext: boolean;
    ownerIds: string[];
    adminIds: string[];
    failUnknownInGroup: boolean;
  };
  authorization: {
    defaultEffect: "deny" | "allow";
    requireMentionInGroups: boolean;
    restrictedTools: string[];
    restrictedDataClasses: Array<Exclude<DataClass, "public">>;
    toolAllowByRole: Record<PrincipalRole, string[]>;
  };
  approval: {
    enabled: boolean;
    ttlSeconds: number;
    requireForTools: string[];
    requireForDataClasses: Array<"restricted" | "secret">;
    ownerQuorum: number;
    bindToConversation: boolean;
    storagePath?: string;
  };
  tenancy: {
    budgetKeyMode: "agent" | "agent+principal+conversation";
    redactCrossPrincipalOutput: boolean;
  };
  outboundGuard: {
    enabled: boolean;
    systemPromptLeakPatterns: string[];
    injectedFileNames: string[];
  };
  rollout: {
    stage: RolloutStage;
    highRiskTools: string[];
  };
  monitoring: {
    falsePositiveThresholdPct: number;
    consecutiveDaysForTuning: number;
  };
  audit: {
    enabled: boolean;
    sinkPath?: string;
  };
  externalValidation?: {
    enabled: boolean;
    endpoint: string;
    timeoutMs?: number;
    validators: string[];
    failOpen: boolean;
  };
  budgetPersistence: {
    enabled: boolean;
    storagePath?: string;
  };
  notifications: {
    enabled: boolean;
    adminChannelId?: string;
  };
}

export interface TokenUsageSummary {
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  recordCount: number;
  byUser: Record<string, { input: number; output: number; total: number }>;
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
  approvalChallenge?: {
    requestId: string;
    expiresAt: number;
    reason: string;
    requiredRole: ApproverRole;
  };
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
