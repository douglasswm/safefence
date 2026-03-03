# OpenClaw Guardrails v3

Native TypeScript security kernel for OpenClaw (`>=2026.2.25`) with deterministic local enforcement, principal-aware authorization, and owner approval for group/multi-user safety.

## Core Model

- One engine path for all phases (`GuardrailsEngine`).
- Declarative policy + deterministic reason codes.
- Monotonic precedence: `DENY > REDACT > ALLOW`.
- No runtime dependency on remote inference or policy services.
- Audit mode still applies redaction by default.

## v3 Security Additions

- Principal-aware identity model (`owner/admin/member/unknown`).
- Group-aware authorization (mention-gating + role tool policy).
- One-time owner approval challenges with TTL, action digest binding, anti-replay.
- Optional persistent approval store (`approval.storagePath`) for restart resilience.
- Principal-partitioned budgets (`agent + principal + conversation`).
- Restricted-info redaction for non-privileged group principals.
- Rollout controls (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`).
- Monitoring snapshot with false-positive threshold signaling.

## OWASP LLM Coverage

- LLM01 Prompt Injection: prompt-intent detector + tool gating.
- LLM02 Sensitive Disclosure: secret/PII redaction + restricted-info controls.
- LLM03 Supply Chain: trusted source and hash policy for `skills.install`.
- LLM04/08/09 Retrieval Trust: trust level + signature checks for high-risk execution.
- LLM05 Improper Output Handling: sanitize and redact untrusted outputs.
- LLM06 Excessive Agency: role-based tool policy + strict command/network/path controls.
- LLM07 System Prompt Leakage: leak pattern denial and output filtering.
- LLM10 Unbounded Consumption: per-principal request/tool budgets.

## Architecture

- `src/core/engine.ts`: ordered detector pipeline + final decisioning.
- `src/core/identity.ts`: principal normalization.
- `src/core/authorization.ts`: role/channel/data-class policy evaluation.
- `src/core/approval-store.ts` + `src/core/approval.ts`: owner approval broker/state.
- `src/core/detectors/*`: security detector modules.
- `src/plugin/openclaw-adapter.ts`: OpenClaw hook adapter + summary telemetry.

## Owner Approval Flow

1. Member in group requests restricted action.
2. Engine returns `DENY` with `OWNER_APPROVAL_REQUIRED` and `approvalChallenge`.
3. Owner/admin approves out-of-band and issues one-time token.
4. Caller retries with `metadata.approval.token` (and optionally `requestId`).
5. Engine verifies TTL, digest, conversation binding, requestId (when provided), and replay status.
6. Valid token allows reevaluation and execution.

## Usage

```ts
import { createOpenClawGuardrailsPlugin } from "@safefence/openclaw-guardrails";

const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  mode: "enforce",
  failClosed: true
});

// Out-of-band owner approval path
const token = plugin.approveRequest(requestId, "owner-user-id", "owner");
```

## v3 Config Example

```ts
const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  principal: {
    requireContext: true,
    ownerIds: ["owner-user-id"],
    adminIds: ["admin-user-id"],
    failUnknownInGroup: true
  },
  authorization: {
    defaultEffect: "deny",
    requireMentionInGroups: true,
    restrictedTools: ["exec", "process", "write", "edit", "apply_patch", "skills.install"],
    restrictedDataClasses: ["internal", "restricted", "secret"],
    toolAllowByRole: {
      owner: ["read", "write", "edit", "exec", "process", "apply_patch", "search", "skills.install"],
      admin: ["read", "write", "edit", "exec", "process", "search"],
      member: ["read", "search"],
      unknown: []
    }
  },
  approval: {
    enabled: true,
    ttlSeconds: 300,
    requireForTools: ["exec", "process", "write", "edit", "apply_patch", "skills.install"],
    requireForDataClasses: ["restricted", "secret"],
    ownerQuorum: 1,
    bindToConversation: true,
    storagePath: "/workspace/project/.openclaw/approval-store.json"
  },
  tenancy: {
    budgetKeyMode: "agent+principal+conversation",
    redactCrossPrincipalOutput: true
  },
  rollout: {
    stage: "stage_c_full_enforce",
    highRiskTools: ["exec", "process", "write", "edit", "apply_patch", "skills.install"]
  },
  monitoring: {
    falsePositiveThresholdPct: 3,
    consecutiveDaysForTuning: 2
  }
});
```

## Migration (v2 -> v3)

1. Add `principal`, `authorization`, `approval`, and `tenancy` blocks.
2. Pass sender/channel metadata in hook contexts (`senderId`, `conversationId`, `channelType`, `mentionedAgent`).
3. Integrate owner approval handling via `approvalChallenge.requestId` + `plugin.approveRequest(...)`.
4. Keep secure defaults unless you have a validated exception.
5. Use `rollout.stage` for staged deployment and monitor `metadata.guardrailsMonitoring`.

## OpenClaw Group Hardening Baseline

- Prefer strict session isolation (`dmScope` narrow mode).
- Use explicit sender/group allowlists.
- Require mention before group tool execution.
- Keep pairing strict; do not allow permissive onboarding.
- Restrict high-risk tools to owner/admin policy paths.

## Limitations

- Deterministic patterns are not a full semantic jailbreak solution.
- Approval token brokering is local in-memory by default (use persistent backing if needed).
- Retrieval trust still depends on upstream metadata quality.

## Development

```bash
npm test
npm run test:coverage
npm run build
```
