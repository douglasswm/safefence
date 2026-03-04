# OpenClaw Guardrails v3

Native TypeScript security kernel for OpenClaw (`>=2026.2.25`) with deterministic local enforcement, principal-aware authorization, and owner approval for group/multi-user safety.

## Repository Context

- Root project overview: [`../../README.md`](../../README.md)
- Research and threat analysis: [`../../docs/openclaw-llm-security-research.md`](../../docs/openclaw-llm-security-research.md)
- OWASP LLM coverage mapping: see the research doc above.

## Core Model

- One engine path for all phases (`GuardrailsEngine`).
- Declarative policy + deterministic reason codes.
- Monotonic precedence: `DENY > REDACT > ALLOW`.
- No runtime dependency on remote inference or policy services.
- Audit mode still applies redaction by default.

## v3 Security Features

- Principal-aware identity model (`owner/admin/member/unknown`).
- **Anti-spoofing**: privileged roles (`owner`/`admin`) are derived exclusively from `principal.ownerIds`/`adminIds` in config — caller-supplied `metadata.role` values of `"owner"` or `"admin"` are downgraded to `"member"`.
- Group-aware authorization (mention-gating + role tool policy).
- One-time owner approval challenges with TTL, action digest binding, anti-replay, and requester identity binding.
- Optional persistent approval store (`approval.storagePath`) with storage path validation (must be within `workspaceRoot`) and expired record pruning.
- **Reason code sanitization**: sensitive internal reason codes (e.g. `PROMPT_INJECTION`) are replaced with `CONTENT_POLICY_VIOLATION` in client-facing output to prevent detection fingerprinting.
- Principal-partitioned budgets (`agent + principal + conversation`).
- Restricted-info redaction for non-privileged group principals.
- Rollout controls (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`).
- Monitoring snapshot with false-positive threshold signaling.

## Architecture

```
src/
├── index.ts                          # Public exports
├── core/
│   ├── engine.ts                     # Ordered detector pipeline + final decisioning
│   ├── identity.ts                   # Principal normalization + anti-spoofing
│   ├── authorization.ts              # Role/channel/data-class policy evaluation
│   ├── approval.ts                   # Owner approval broker
│   ├── approval-store.ts             # Persistent approval state + pruning
│   ├── budget-store.ts               # Per-principal budget tracking
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

**Exported types**: `ApproverRole`, `ChannelType`, `DataClass`, `Decision`, `PrincipalContext`, `PrincipalRole`, `RolloutStage`, `GuardDecision`, `GuardEvent`, `GuardrailsConfig`, `Phase`.

**Exported constants**: `REASON_CODES`, `UNKNOWN_SENDER`, `UNKNOWN_CONVERSATION`.

**Config helpers**: `createDefaultConfig()`, `mergeConfig(base, overrides)`.

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

## Migration (v2 -> v3)

1. Add `principal`, `authorization`, `approval`, and `tenancy` blocks.
2. Pass sender/channel metadata in hook contexts (`senderId`, `conversationId`, `channelType`, `mentionedAgent`).
3. Integrate owner approval handling via `approvalChallenge.requestId` + `plugin.approveRequest(...)`.
4. Keep secure defaults unless you have a validated exception.
5. Use `rollout.stage` for staged deployment and monitor `metadata.guardrailsMonitoring`.
6. **Breaking**: callers can no longer self-assign privileged roles (`owner`/`admin`) via `metadata.role`. Privileged roles are now derived exclusively from `principal.ownerIds`/`adminIds` in config. Any caller-supplied `"owner"` or `"admin"` role is downgraded to `"member"`.

## Limitations

- Deterministic patterns are not a full semantic jailbreak solution.
- Persistent approval store prunes expired records on write; replayed tokens are still caught within the TTL window. Approval tokens survive restarts when `storagePath` is configured.
- Retrieval trust still depends on upstream metadata quality.

## Development

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```
