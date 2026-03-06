# OpenClaw Guardrails

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Native TypeScript security kernel for OpenClaw (`>=2026.2.25`) with deterministic local enforcement, principal-aware authorization, and owner approval for group/multi-user safety.

## Repository Context

- Root project overview: [`../../README.md`](../../README.md)
- Research and threat analysis: [`../../docs/openclaw-llm-security-research.md`](../../docs/openclaw-llm-security-research.md)
- OWASP LLM coverage mapping: see the research doc above.

## Core Model

- One engine path for all phases (`GuardrailsEngine`).
- Fixed-order detector pipeline with deterministic reason codes.
- Monotonic precedence: `DENY > REDACT > ALLOW`.
- No runtime dependency on remote inference or policy services.
- Zero runtime dependencies — uses only Node.js built-ins (`fetch()`, `fs`).
- Audit mode still applies redaction by default.

## Security Features

### Identity and Authorization
- Principal-aware identity model (`owner/admin/member/unknown`).
- **Anti-spoofing**: privileged roles (`owner`/`admin`) are derived exclusively from `principal.ownerIds`/`adminIds` in config — caller-supplied `metadata.role` values of `"owner"` or `"admin"` are downgraded to `"member"`.
- Group-aware authorization (mention-gating + role-based tool policy).

### Approval Workflow
- One-time owner approval challenges with TTL, action digest binding, anti-replay, and requester identity binding.
- Optional persistent approval store (`approval.storagePath`) with storage path validation (must be within `workspaceRoot`) and expired record pruning.
- Admin notification bridge (`NotificationSink`) for cross-session approval alerts. Ships with `ConsoleNotificationSink`, `CallbackNotificationSink`, and `NoopNotificationSink`.

### Detection Pipeline
- Prompt injection pattern matching on inbound content.
- Command allow/deny policy enforcement with shell operator blocking.
- Path canonicalization with symlink traversal detection.
- Network egress validation (host allowlist, private IP blocking).
- Supply chain verification (skill source trust + hash integrity).
- Sensitive data detection and redaction (secrets, PII) via regex patterns.
- Output safety checks for system prompt leaks and injected filename references.
- Restricted-info redaction for non-privileged group principals.

### Operational Controls
- **Reason code sanitization**: sensitive internal reason codes (e.g. `PROMPT_INJECTION`) are replaced with `CONTENT_POLICY_VIOLATION` in client-facing output to prevent detection fingerprinting.
- Principal-partitioned budgets (`agent + principal + conversation`).
- Staged rollout controls (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`).
- Monitoring snapshot with false-positive threshold signaling.
- Fail-closed by default — engine errors result in `DENY` unless explicitly configured otherwise.

### Extensibility
- **Immutable JSONL audit trail**: every `evaluate()` call optionally emits a structured `AuditEvent` to a JSONL file via `AuditSink`. Enable with `audit.enabled` + `audit.sinkPath`.
- **Custom business rule validators**: inject domain-specific logic (spending limits, data access boundaries) via the `CustomValidator` interface without forking. Validators are phase-filtered and run concurrently with external validators.
- **External validator integration**: optional HTTP-based semantic validation (jailbreak detection, PII scanning) via configurable endpoint. Circuit breaker (3 failures → 60s cooldown), configurable timeout, fail-open mode.
- **Per-user token usage tracking**: records input/output token counts per user/conversation/tool via `TokenUsageStore`. JSONL persistence, per-user aggregation summaries emitted at `agent_end`.

## Architecture

```
src/
├── index.ts                          # Public exports
├── core/
│   ├── engine.ts                     # Ordered detector pipeline + final decisioning
│   ├── identity.ts                   # Principal normalization + anti-spoofing
│   ├── authorization.ts              # Role/channel/data-class policy evaluation
│   ├── approval.ts                   # Owner approval broker + notification sink
│   ├── approval-store.ts             # Persistent approval state + pruning
│   ├── audit-sink.ts                 # JSONL audit event sink
│   ├── budget-store.ts               # Per-principal budget tracking
│   ├── custom-validator.ts           # Custom validator interface
│   ├── jsonl-writer.ts               # Shared JSONL append writer
│   ├── notification-sink.ts          # Admin notification sink interface + impls
│   ├── token-usage-store.ts          # Per-user token usage tracking
│   ├── normalize.ts                  # Event normalization
│   ├── event-utils.ts                # Guard event helpers
│   ├── scoring.ts                    # Risk score aggregation
│   ├── reason-codes.ts               # Canonical reason code constants
│   ├── types.ts                      # Core type definitions
│   ├── command-parse.ts              # Command string parsing
│   ├── network-guard.ts              # Network host/URL validation
│   ├── path-canonical.ts             # Path canonicalization + symlink checks
│   ├── retrieval-trust.ts            # Retrieval trust level evaluation
│   ├── supply-chain.ts               # Skill source + hash policy
│   └── detectors/                    # Security detector modules
│       └── external-validator-detector.ts  # HTTP external validation + circuit breaker
├── plugin/
│   ├── openclaw-adapter.ts           # OpenClaw hook adapter + summary telemetry
│   └── openclaw-extension.ts         # Plugin entry point (registerOpenClawGuardrails)
├── redaction/
│   └── redact.ts                     # Secret/PII redaction engine
└── rules/
    ├── default-policy.ts             # Default config factory + merge
    └── patterns.ts                   # Detection pattern definitions
```

## Owner Approval Flow

1. Member in group requests a restricted action.
2. Engine returns `DENY` with `OWNER_APPROVAL_REQUIRED` and `approvalChallenge`.
3. Owner/admin approves out-of-band and issues one-time token.
4. Caller retries with `metadata.approval.token` (and optionally `requestId`).
5. Engine verifies TTL, digest, conversation binding, requester identity binding, requestId (when provided), and replay status.
6. Valid token allows reevaluation and execution.

When `notifications.enabled` is true and a `NotificationSink` is configured, the broker automatically notifies admins when a new approval challenge is created.

Approval works across all channel types (DM, group, thread), not just groups — group context merely triggers the initial challenge for restricted actions.

## Install in OpenClaw

```bash
openclaw plugins install @safefence/openclaw-guardrails
openclaw plugins list
```

### Configure `openclaw.config.ts`

```ts
import { defineConfig } from "openclaw/config";

export default defineConfig({
  plugins: {
    entries: {
      "openclaw-guardrails": {
        enabled: true,
        config: {
          workspaceRoot: "/workspace/project",
          mode: "enforce",
          failClosed: true
        }
      }
    }
  }
});
```

After changing plugin install/config, restart the OpenClaw service or gateway process so hook registration is reloaded.

## Usage

Three main entry points:

```ts
// 1. Plugin factory — returns an OpenClaw-compatible plugin with hook handlers
import { createOpenClawGuardrailsPlugin } from "@safefence/openclaw-guardrails";

const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  mode: "enforce",
  failClosed: true
});

// Out-of-band owner approval
const token = plugin.approveRequest(requestId, "owner-user-id", "owner");

// 2. OpenClaw extension entry — auto-registers all hooks from plugin config
import { registerOpenClawGuardrails } from "@safefence/openclaw-guardrails";
registerOpenClawGuardrails(api);

// 3. Engine directly — for custom integrations outside OpenClaw
import { GuardrailsEngine } from "@safefence/openclaw-guardrails";
const engine = new GuardrailsEngine(config);
const decision = await engine.evaluate(event);
```

### Plugin with advanced options

```ts
import {
  createOpenClawGuardrailsPlugin,
  JsonlAuditSink,
  CallbackNotificationSink
} from "@safefence/openclaw-guardrails";

const plugin = createOpenClawGuardrailsPlugin({
  config: {
    workspaceRoot: "/workspace/project",
    audit: { enabled: true, sinkPath: "/var/log/guardrails/audit.jsonl" },
    budgetPersistence: { enabled: true, storagePath: "/data/token-usage.jsonl" },
    notifications: { enabled: true },
    externalValidation: {
      enabled: true,
      endpoint: "https://guard.example.com/validate",
      validators: ["jailbreak", "pii"],
      timeoutMs: 3000,
      failOpen: true
    }
  },
  auditSink: new JsonlAuditSink("/var/log/guardrails/audit.jsonl"),
  notificationSink: new CallbackNotificationSink(async (notification) => {
    await sendSlackMessage(adminChannel, `Approval needed: ${notification.reason}`);
  })
});
```

### Custom validators

```ts
import { GuardrailsEngine } from "@safefence/openclaw-guardrails";
import type { CustomValidator } from "@safefence/openclaw-guardrails";

const spendingLimit: CustomValidator = {
  id: "spending-limit",
  phases: ["before_tool_call"],
  validate({ event }) {
    if (event.toolName === "purchase" && event.args.amount > 1000) {
      return [{ ruleId: "spending-limit", reasonCode: "OVER_LIMIT", decision: "DENY", weight: 1 }];
    }
    return [];
  }
};

const engine = new GuardrailsEngine(config, { customValidators: [spendingLimit] });
```

**Exported types**: `ApproverRole`, `ChannelType`, `DataClass`, `Decision`, `PrincipalContext`, `PrincipalRole`, `RolloutStage`, `GuardDecision`, `GuardEvent`, `GuardrailsConfig`, `Phase`, `TokenUsageSummary`, `AuditEvent`, `AuditSink`, `CustomValidator`, `CustomValidatorContext`, `NotificationSink`, `ApprovalNotification`, `TokenUsageRecord`, `EngineOptions`, `PluginOptions`.

**Exported constants**: `REASON_CODES`, `UNKNOWN_SENDER`, `UNKNOWN_CONVERSATION`.

**Exported classes**: `GuardrailsEngine`, `JsonlAuditSink`, `NoopAuditSink`, `ConsoleNotificationSink`, `CallbackNotificationSink`, `NoopNotificationSink`, `TokenUsageStore`.

**Config helpers**: `createDefaultConfig()`, `mergeConfig(base, overrides)`.

## Config Reference

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| `audit` | `enabled` | `boolean` | `false` | Enable JSONL audit trail |
| `audit` | `sinkPath` | `string?` | — | File path for JSONL audit events |
| `externalValidation` | `enabled` | `boolean` | `false` | Enable HTTP external validators |
| `externalValidation` | `endpoint` | `string` | — | POST endpoint for validation requests |
| `externalValidation` | `timeoutMs` | `number?` | `5000` | Per-request timeout |
| `externalValidation` | `validators` | `string[]` | `[]` | Validator names to invoke |
| `externalValidation` | `failOpen` | `boolean` | `false` | Allow on timeout/error |
| `budgetPersistence` | `enabled` | `boolean` | `false` | Enable token usage tracking |
| `budgetPersistence` | `storagePath` | `string?` | — | JSONL path for usage persistence |
| `notifications` | `enabled` | `boolean` | `false` | Enable approval notifications |
| `notifications` | `adminChannelId` | `string?` | — | Target channel for notifications |

## Config Example (Minimal Overrides)

Most config has secure defaults. Override only what you need:

```ts
const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  principal: {
    ownerIds: ["owner-user-id"],
    adminIds: ["admin-user-id"]
  },
  approval: {
    enabled: true,
    storagePath: "/workspace/project/.openclaw/approval-store.json"
  }
});
```

See the [research doc](../../docs/openclaw-llm-security-research.md) for a full config reference with all fields.

## Migration

### v0.5.x → v0.6.0

1. `GuardrailsEngine` constructor now takes `(config, options?)` instead of `(config, budgetStore?, approvalBroker?)`. Pass dependencies via `EngineOptions`.
2. `createOpenClawGuardrailsPlugin()` accepts both `Partial<GuardrailsConfig>` (unchanged) and `PluginOptions` (new) for injecting audit sinks, notification sinks, etc.
3. New config sections (`audit`, `externalValidation`, `budgetPersistence`, `notifications`) default to disabled — no breaking changes for existing configs.
4. New reason codes: `EXTERNAL_VALIDATION_FAILED`, `EXTERNAL_VALIDATION_TIMEOUT`.

### v0.3.x → v0.4.0

1. Add `principal`, `authorization`, `approval`, and `tenancy` config blocks.
2. Pass sender/channel metadata in hook contexts (`senderId`, `conversationId`, `channelType`, `mentionedAgent`).
3. Integrate owner approval handling via `approvalChallenge.requestId` + `plugin.approveRequest(...)`.
4. Keep secure defaults unless you have a validated exception.
5. Use `rollout.stage` for staged deployment and monitor `metadata.guardrailsMonitoring`.
6. **Breaking**: callers can no longer self-assign privileged roles (`owner`/`admin`) via `metadata.role`. Privileged roles are now derived exclusively from `principal.ownerIds`/`adminIds` in config. Any caller-supplied `"owner"` or `"admin"` role is downgraded to `"member"`.

## Limitations

- Deterministic patterns are not a full semantic jailbreak solution.
- Persistent approval store prunes expired records on write; replayed tokens are still caught within the TTL window. Approval tokens survive restarts when `storagePath` is configured.
- Retrieval trust still depends on upstream metadata quality.
- External validator circuit breaker state is module-scoped (shared across engine instances in the same process).
- Token usage `records` array grows unboundedly in memory for long-running processes. Use JSONL persistence and restart periodically for high-volume deployments.

## Development

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```
