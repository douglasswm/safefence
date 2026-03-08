# SafeFence

[![npm version](https://img.shields.io/npm/v/@safefence/openclaw-guardrails)](https://www.npmjs.com/package/@safefence/openclaw-guardrails)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)
[![CI](https://github.com/douglasswm/safefence/actions/workflows/publish.yml/badge.svg)](https://github.com/douglasswm/safefence/actions/workflows/publish.yml)

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Security-focused tooling for hardening OpenClaw agent deployments, with emphasis on OWASP LLM Top 10 controls, deterministic guardrails, and multi-user safety.

## Repository Layout

- `packages/openclaw-guardrails`: production TypeScript guardrails library/plugin.
- `packages/control-plane`: centralized control plane API (Hono + PostgreSQL + Redis).
- `packages/dashboard`: Next.js admin dashboard for policy, RBAC, fleet, and audit management.
- `docs/openclaw-llm-security-research.md`: threat research, OWASP mapping, and hardening guidance.
- `docs/rbac-research.md`: RBAC and adaptive guardrails strategic framework.
- `CLAUDE.md`: local engineering workflow and coding standards.

## What This Project Delivers

A deterministic security plugin for OpenClaw agents — no remote inference, zero runtime dependencies. Now with optional centralized control plane for multi-instance fleet management. Current version: `0.8.0`.

### Detection Pipeline
- Fixed-order detector pipeline (12 detectors): input intent (prompt injection, exfiltration, context probing), command policy, path canonicalization, network egress, supply chain provenance, principal authorization, owner approval, sensitive data, restricted-info redaction, output safety, budget enforcement, and external/custom validators.
- Monotonic precedence: `DENY > REDACT > ALLOW`.

### Identity and Access Control
- Dual-authorization model (user RBAC ∩ bot capabilities) with anti-spoofing.
- Persistent RBAC store (SQLite) with per-user, per-bot, per-channel role assignments.
- Bot instances as first-class entities with capability ceilings and access policies.
- Bot commands (`/sf`), HTTP admin API, and CLI for dynamic role management without restart.
- Zero-config bootstrap: `/sf setup` claims first ownership without config file edits.
- Dynamic RBAC role resolution: store-first lookup before config fallback.
- Group-aware mention-gating and role-based tool policy.
- Owner-approval workflow with TTL, anti-replay, conversation binding, and optional persistence.
- Admin notification bridge for approval workflow alerts.

### Extensibility
- Immutable JSONL audit trail for every evaluation.
- Runtime policy store: 22 config fields changeable via `/sf policy set` without restart, persisted in SQLite.
- Custom business rule validators for domain-specific logic.
- Optional external HTTP validators with circuit breaker (e.g. Guardrails AI).
- Per-user token usage tracking with JSONL persistence.
- Hash-chained, tamper-evident RBAC audit log (separate SQLite DB) for authorization decisions and admin mutations.

### Control Plane (Optional SaaS)
- Centralized policy, RBAC, and audit management across all OpenClaw instances in an organization.
- Hybrid notify-then-pull sync: SSE push notifications trigger REST delta pulls.
- Local SQLite acts as write-through cache — enforcement continues offline with cached state.
- Streaming audit upload with batched REST and cursor-based acknowledgment.
- Multi-tenant PostgreSQL with Row-Level Security per organization.
- Next.js dashboard for org overview, instance fleet, policy editor, RBAC admin, and audit viewer.
- Plugin works standalone when `controlPlane.enabled: false` (default).

### Operational Controls
- Staged rollout (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`).
- Runtime monitoring snapshot with false-positive threshold signaling.
- Fail-closed by default.
- 186 tests across 22 test files at ~85% line coverage.

## How It Works

### End-to-End Flow

Every agent lifecycle event passes through the guardrails plugin before reaching the agent or the user.

```mermaid
sequenceDiagram
    participant U as User / Channel
    participant OC as OpenClaw Runtime
    participant EXT as openclaw-extension.ts
    participant ADP as openclaw-adapter.ts
    participant ENG as GuardrailsEngine
    participant DET as Detector Pipeline

    U->>OC: Send message
    OC->>EXT: message_received(event, ctx)
    EXT->>ADP: hooks.message_received(oclCtx)
    ADP->>ADP: toEvent("message_received", ctx)
    ADP->>ADP: Dual-auth check (user RBAC ∩ bot caps)
    Note over ADP: If RBAC denies, request never reaches detectors
    ADP->>ENG: engine.evaluate(guardEvent, phase)
    ENG->>DET: Run 12 detectors sequentially
    DET-->>ENG: RuleHit[]
    ENG->>ENG: decideFromHits() → DENY > REDACT > ALLOW
    ENG->>ENG: aggregateRisk() → 0–1 score
    ENG->>ENG: finalizeDecision() (audit mode override)
    ENG-->>ADP: GuardDecision
    ADP->>ADP: applyRolloutPolicy()
    ADP->>ADP: updateMetrics()
    ADP-->>EXT: OpenClawHookResult
    Note over EXT: message_received is observe-only
    EXT-->>OC: void (cannot block)

    OC->>EXT: before_tool_call(event, ctx)
    EXT->>ADP: hooks.before_tool_call(oclCtx)
    ADP->>ENG: engine.evaluate(guardEvent, phase)
    ENG->>DET: Run 12 detectors
    DET-->>ENG: RuleHit[]
    ENG-->>ADP: GuardDecision
    ADP-->>EXT: OpenClawHookResult
    EXT-->>OC: { block: true, blockReason } or {}

    OC->>EXT: message_sending(event, ctx)
    EXT->>ADP: hooks.message_sending(oclCtx)
    ADP->>ADP: extractOutboundContent() (all string fields)
    ADP->>ENG: engine.evaluate(guardEvent, phase)
    ENG->>DET: Run 12 detectors
    DET-->>ENG: RuleHit[]
    ENG-->>ADP: GuardDecision
    ADP-->>EXT: OpenClawHookResult
    EXT-->>OC: { cancel: true } or { content: redacted } or {}
```

### Detector Pipeline

All 12 detectors run sequentially for every evaluation. No short-circuiting — an early DENY does not skip later detectors.

```mermaid
sequenceDiagram
    participant ENG as Engine.evaluate()
    participant D1 as 1. Input Intent
    participant D2 as 2. Command Policy
    participant D3 as 3. Path Canonical
    participant D4 as 4. Network Egress
    participant D5 as 5. Provenance
    participant D6 as 6. Principal Authz
    participant D7 as 7. Owner Approval
    participant D8 as 8. Sensitive Data
    participant D9 as 9. Restricted Info
    participant D10 as 10. Output Safety
    participant D11 as 11. Budget
    participant D12 as 12. Extensions

    ENG->>D1: size limits, injection, exfil, context probes
    D1-->>ENG: hits[]
    ENG->>D2: tool allowlist, command policy, shell ops
    D2-->>ENG: hits[]
    ENG->>D3: path traversal, workspace boundary, symlinks
    D3-->>ENG: hits[] (async: realpath)
    ENG->>D4: host allowlist, private egress, DNS
    D4-->>ENG: hits[] (async: DNS resolve)
    ENG->>D5: supply chain + retrieval trust
    D5-->>ENG: hits[] (async)
    ENG->>D6: dual-auth (user RBAC ∩ bot caps), mention-gating
    D6-->>ENG: hits[] + approvalRequirement?
    ENG->>D7: challenge/verify approval token
    Note over D7: Only if D6 returned approvalRequirement
    D7-->>ENG: hits[] + approvalChallenge?
    ENG->>D8: secret & PII redaction
    D8-->>ENG: hits[] + redactedContent?
    ENG->>D9: data-class redaction for non-owners
    D9-->>ENG: hits[] + redactedContent?
    ENG->>D10: system prompt leak, suspicious output
    Note over D10: Receives redactedContent from D9/D8
    D10-->>ENG: hits[] + redactedContent?
    ENG->>D11: rate limits (requests/min, tool calls/min)
    D11-->>ENG: hits[]
    ENG->>D12: external HTTP validators + custom validators
    Note over D12: Run concurrently via Promise.all
    D12-->>ENG: hits[]
    ENG->>ENG: Merge all hits → decide → score → finalize
```

### Owner Approval Workflow

```mermaid
sequenceDiagram
    participant Agent as Agent
    participant ENG as GuardrailsEngine
    participant AB as ApprovalBroker
    participant NS as NotificationSink
    participant Owner as Owner / Admin

    Agent->>ENG: before_tool_call (restricted tool)
    ENG->>ENG: D6 Principal Authz → approvalRequirement
    ENG->>AB: createChallenge(toolName, args, requesterId)
    AB->>AB: Generate requestId, compute actionDigest (SHA-256)
    AB->>NS: notify({ requestId, toolName, reason, ... })
    AB-->>ENG: { requestId, expiresAt, reason, requiredRole }
    ENG-->>Agent: DENY + approvalChallenge

    Owner->>ENG: /approve <requestId>
    ENG->>AB: approveRequest(requestId, ownerId, "owner")
    AB->>AB: Verify: not expired, role sufficient, not self-approval
    AB->>AB: Check quorum, generate token (apr_<uuid>)
    AB-->>ENG: token
    ENG-->>Owner: "Approved. Token: apr_..."

    Agent->>ENG: before_tool_call (same tool + approval.token)
    ENG->>AB: verifyAndConsumeToken(token)
    AB->>AB: Verify: not expired, not replayed, conversation match, action digest match
    AB->>AB: Mark token used
    AB-->>ENG: "valid"
    ENG-->>Agent: ALLOW
```

### Control Plane Architecture

When `controlPlane.enabled` is set, each plugin instance connects to the centralized control plane:

```
┌────────────────────────────────────────────────────────┐
│  SafeFence Cloud (control-plane package)               │
│                                                        │
│  REST API ◄──► PostgreSQL (RLS per org)                │
│  SSE Broadcast ◄──► Redis pub/sub                      │
│  Dashboard (Next.js) ◄──► REST API                     │
└────────────┬──────────────────────▲────────────────────┘
             │ Policy/RBAC sync     │ Audit events
             │ (SSE + REST pull)    │ (REST batch POST)
             │                      │
┌────────────▼──────────────────────┴────────────────────┐
│  OpenClaw Instance                                     │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ @safefence/openclaw-guardrails                    │  │
│  │  GuardrailsEngine → 12 detectors (local, fast)   │  │
│  │  SyncRoleStore (wraps SqliteRoleStore + syncs)    │  │
│  │  StreamingAuditSink (wraps AuditSink + streams)   │  │
│  │  PolicySyncLoop + RbacSyncLoop (SSE-triggered)    │  │
│  │  ControlPlaneAgent (registration + heartbeat)     │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

Key design principle: **detectors always run locally**. The control plane is never in the hot path. Sub-millisecond evaluation is preserved. Local SQLite acts as a write-through cache — if disconnected, enforcement continues against cached state.

## Quick Start (Current Package)

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```

## Quick Start (Control Plane)

```bash
# Start PostgreSQL + Redis + control plane
cd packages/control-plane
docker compose up -d

# Start the dashboard
cd packages/dashboard
npm install && npm run dev
# → Dashboard at http://localhost:3000

# Create an organization (returns an API key)
curl -X POST http://localhost:3100/api/v1/orgs \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Org"}'

# Configure plugin instances to connect
# In openclaw.config.ts:
#   controlPlane: {
#     enabled: true,
#     endpoint: "http://localhost:3100",
#     orgApiKey: "sf_..."
#   }
```

## Release Workflow

Releases are published automatically via GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). Every published version includes a Sigstore-signed attestation linking the package to the exact source commit and CI workflow.

```bash
# 1. Bump version from the package directory
#    (npm version must run where package.json lives)
cd packages/openclaw-guardrails
npm version patch   # or: minor | major

# 2. npm version updates package.json and package-lock.json, but the
#    version sync script also modifies openclaw.plugin.json, version.ts,
#    and the root README.md. These changes are staged but NOT committed
#    automatically — commit them yourself:
cd ../..
git add -A
git commit -m "chore: bump version to $(node -p "require('./packages/openclaw-guardrails/package.json').version")"

# 3. Tag and push — the v* tag triggers CI to publish to npm
git tag "v$(node -p "require('./packages/openclaw-guardrails/package.json').version")"
git push origin master --tags

# 4. Verify provenance after CI completes
npm audit signatures
```

`npm version` must be run from `packages/openclaw-guardrails/` because it operates on that directory's `package.json`. It runs tests and builds via `preversion`, then syncs the version to `openclaw.plugin.json`, `src/plugin/version.ts`, and the root `README.md` via `scripts/sync-version.sh`. However, because this is a monorepo subdirectory, npm's auto-commit does not reliably capture all synced files — you must commit and tag manually.

Pushing the `v*` tag triggers `.github/workflows/publish.yml`, which runs `npm publish` with provenance enabled via `publishConfig` in `package.json` and GitHub OIDC — no manual signing keys required.

Ensure `package.json` has `openclaw.extensions` pointing to `./dist/plugin/openclaw-extension.js`, and the tarball includes `dist/**`, `openclaw.plugin.json`, and `README.md`.

## Documentation

- Guardrails plugin: [`packages/openclaw-guardrails/README.md`](./packages/openclaw-guardrails/README.md)
- Control plane API: [`packages/control-plane/`](./packages/control-plane/)
- Dashboard: [`packages/dashboard/`](./packages/dashboard/)
- Research report: [`docs/openclaw-llm-security-research.md`](./docs/openclaw-llm-security-research.md)
- RBAC research: [`docs/rbac-research.md`](./docs/rbac-research.md)

## Compatibility

- OpenClaw target: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`
