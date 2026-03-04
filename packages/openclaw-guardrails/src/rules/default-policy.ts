import type { GuardrailsConfig } from "../core/types.js";
import {
  DEFAULT_COMMAND_PATTERNS,
  DEFAULT_EXFILTRATION_PATTERNS,
  DEFAULT_PATH_PATTERNS,
  DEFAULT_PII_PATTERNS,
  DEFAULT_PROMPT_INJECTION_PATTERNS,
  DEFAULT_SHELL_OPERATOR_PATTERNS,
  DEFAULT_SECRET_PATTERNS
} from "./patterns.js";

export function createDefaultConfig(workspaceRoot: string): GuardrailsConfig {
  const defaultRestrictedTools = [
    "exec",
    "process",
    "write",
    "edit",
    "apply_patch",
    "skills.install"
  ];

  return {
    mode: "enforce",
    failClosed: true,
    workspaceRoot,
    allow: {
      tools: [
        "read",
        "write",
        "edit",
        "exec",
        "process",
        "apply_patch",
        "search",
        "skills.install"
      ],
      commands: [
        { binary: "ls" },
        { binary: "cat" },
        { binary: "rg" },
        { binary: "find" },
        { binary: "pwd" },
        { binary: "echo" },
        { binary: "git", argPattern: "^(status|diff)(\\s+.*)?$" },
        { binary: "npm", argPattern: "^(test|run\\s+test)(\\s+.*)?$" }
      ],
      writablePaths: [workspaceRoot],
      networkHosts: ["localhost", "127.0.0.1", "::1"],
      allowPrivateEgress: false
    },
    deny: {
      commandPatterns: DEFAULT_COMMAND_PATTERNS,
      pathPatterns: DEFAULT_PATH_PATTERNS,
      promptInjectionPatterns: DEFAULT_PROMPT_INJECTION_PATTERNS,
      exfiltrationPatterns: DEFAULT_EXFILTRATION_PATTERNS,
      shellOperatorPatterns: DEFAULT_SHELL_OPERATOR_PATTERNS
    },
    redaction: {
      secretPatterns: DEFAULT_SECRET_PATTERNS,
      piiPatterns: DEFAULT_PII_PATTERNS,
      replacement: "[REDACTED]",
      applyInAuditMode: true
    },
    limits: {
      maxInputChars: 20_000,
      maxToolArgChars: 10_000,
      maxOutputChars: 50_000,
      maxRequestsPerMinute: 120,
      maxToolCallsPerMinute: 60
    },
    pathPolicy: {
      enforceCanonicalRealpath: true,
      denySymlinkTraversal: true
    },
    supplyChain: {
      trustedSkillSources: [
        "https://github.com/openclaw/",
        "https://github.com/knostic/",
        "github.com/openclaw/",
        "github.com/knostic/"
      ],
      requireSkillHash: true,
      allowedSkillHashes: []
    },
    retrievalTrust: {
      requiredForToolExecution: true,
      minimumTrustLevel: "medium",
      requireSignedSource: false
    },
    principal: {
      requireContext: true,
      ownerIds: [],
      adminIds: [],
      failUnknownInGroup: true
    },
    authorization: {
      defaultEffect: "deny",
      requireMentionInGroups: true,
      restrictedTools: defaultRestrictedTools,
      restrictedDataClasses: ["internal", "restricted", "secret"],
      toolAllowByRole: {
        owner: [
          "read",
          "write",
          "edit",
          "exec",
          "process",
          "apply_patch",
          "search",
          "skills.install"
        ],
        admin: ["read", "write", "edit", "exec", "process", "search"],
        member: ["read", "search"],
        unknown: []
      }
    },
    approval: {
      enabled: true,
      ttlSeconds: 300,
      requireForTools: defaultRestrictedTools,
      requireForDataClasses: ["restricted", "secret"],
      ownerQuorum: 1,
      bindToConversation: true,
      storagePath: undefined
    },
    tenancy: {
      budgetKeyMode: "agent+principal+conversation",
      redactCrossPrincipalOutput: true
    },
    outboundGuard: {
      enabled: true,
      systemPromptLeakPatterns: [
        "security policy (immutable)",
        "immutable security policy",
        "# system prompt",
        "begin system prompt",
        "here is my system prompt",
        "here are my instructions",
        ".openclaw",
        "heartbeat.md",
        "bootstrap.md",
        "identity.md"
      ],
      injectedFileNames: [
        "agents.md",
        "soul.md",
        "bootstrap.md",
        "heartbeat.md",
        "identity.md",
        "tools.md",
        "user.md",
        ".openclaw/",
        ".openclaw"
      ]
    },
    rollout: {
      stage: "stage_c_full_enforce",
      highRiskTools: defaultRestrictedTools
    },
    monitoring: {
      falsePositiveThresholdPct: 3,
      consecutiveDaysForTuning: 2
    }
  };
}

export function mergeConfig(
  base: GuardrailsConfig,
  overrides: Partial<GuardrailsConfig>
): GuardrailsConfig {
  const retrievalTrust =
    overrides.retrievalTrust || base.retrievalTrust
      ? {
          requiredForToolExecution:
            overrides.retrievalTrust?.requiredForToolExecution ??
            base.retrievalTrust?.requiredForToolExecution ??
            true,
          minimumTrustLevel:
            overrides.retrievalTrust?.minimumTrustLevel ??
            base.retrievalTrust?.minimumTrustLevel ??
            "medium",
          requireSignedSource:
            overrides.retrievalTrust?.requireSignedSource ??
            base.retrievalTrust?.requireSignedSource ??
            false
        }
      : undefined;

  return {
    ...base,
    ...overrides,
    allow: {
      ...base.allow,
      ...(overrides.allow ?? {})
    },
    deny: {
      ...base.deny,
      ...(overrides.deny ?? {})
    },
    redaction: {
      ...base.redaction,
      ...(overrides.redaction ?? {})
    },
    limits: {
      ...base.limits,
      ...(overrides.limits ?? {})
    },
    pathPolicy: {
      ...base.pathPolicy,
      ...(overrides.pathPolicy ?? {})
    },
    supplyChain: {
      ...base.supplyChain,
      ...(overrides.supplyChain ?? {})
    },
    retrievalTrust,
    principal: {
      ...base.principal,
      ...(overrides.principal ?? {})
    },
    authorization: {
      ...base.authorization,
      ...(overrides.authorization ?? {}),
      toolAllowByRole: {
        ...base.authorization.toolAllowByRole,
        ...(overrides.authorization?.toolAllowByRole ?? {})
      }
    },
    approval: {
      ...base.approval,
      ...(overrides.approval ?? {})
    },
    tenancy: {
      ...base.tenancy,
      ...(overrides.tenancy ?? {})
    },
    outboundGuard: {
      ...base.outboundGuard,
      ...(overrides.outboundGuard ?? {})
    },
    rollout: {
      ...base.rollout,
      ...(overrides.rollout ?? {})
    },
    monitoring: {
      ...base.monitoring,
      ...(overrides.monitoring ?? {})
    }
  };
}
