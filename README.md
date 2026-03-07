# SafeFence

[![npm version](https://img.shields.io/npm/v/@safefence/openclaw-guardrails)](https://www.npmjs.com/package/@safefence/openclaw-guardrails)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)
[![CI](https://github.com/douglasswm/safefence/actions/workflows/publish.yml/badge.svg)](https://github.com/douglasswm/safefence/actions/workflows/publish.yml)

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Security-focused tooling for hardening OpenClaw agent deployments, with emphasis on OWASP LLM Top 10 controls, deterministic guardrails, and multi-user safety.

## Repository Layout

- `packages/openclaw-guardrails`: production TypeScript guardrails library/plugin.
- `docs/openclaw-llm-security-research.md`: threat research, OWASP mapping, and hardening guidance.
- `docs/rbac-research.md`: RBAC and adaptive guardrails strategic framework.
- `CLAUDE.md`: local engineering workflow and coding standards.

## What This Project Delivers

A deterministic security plugin for OpenClaw agents — no remote inference, zero runtime dependencies. Current version: `0.6.2`.

### Detection Pipeline
- Fixed-order detector pipeline (12 detectors): input intent (prompt injection, exfiltration, context probing), command policy, path canonicalization, network egress, supply chain provenance, principal authorization, owner approval, sensitive data, restricted-info redaction, output safety, budget enforcement, and external/custom validators.
- Monotonic precedence: `DENY > REDACT > ALLOW`.

### Identity and Access Control
- Principal-aware authorization (`owner/admin/member/unknown`) with anti-spoofing.
- Group-aware mention-gating and role-based tool policy.
- Owner-approval workflow with TTL, anti-replay, conversation binding, and optional persistence.
- Admin notification bridge for approval workflow alerts.

### Extensibility
- Immutable JSONL audit trail for every evaluation.
- Custom business rule validators for domain-specific logic.
- Optional external HTTP validators with circuit breaker (e.g. Guardrails AI).
- Per-user token usage tracking with JSONL persistence.

### Operational Controls
- Staged rollout (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`).
- Runtime monitoring snapshot with false-positive threshold signaling.
- Fail-closed by default.
- 112 tests across 19 test files at ~85% line coverage.

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
    ENG->>D6: identity resolution, RBAC, mention-gating
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

## Quick Start (Current Package)

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```

## Release Workflow

Releases are published automatically via GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). Every published version includes a Sigstore-signed attestation linking the package to the exact source commit and CI workflow.

```bash
cd packages/openclaw-guardrails

# 1. Bump version (runs tests, builds, syncs all version references, commits, tags)
npm version patch   # or: npm version minor | npm version major

# 2. Push to GitHub — CI publishes to npm with provenance
git push origin master --tags

# 3. Verify provenance
npm audit signatures
```

`npm version` automatically: runs tests, builds, syncs the version to `openclaw.plugin.json`, `src/plugin/version.ts`, and the root `README.md`, then commits and tags. The publish workflow (`.github/workflows/publish.yml`) handles `npm publish --provenance` using GitHub OIDC — no manual signing keys required.

Ensure `package.json` has `openclaw.extensions` pointing to `./dist/plugin/openclaw-extension.js`, and the tarball includes `dist/**`, `openclaw.plugin.json`, and `README.md`.

## Documentation

- Package docs: [`packages/openclaw-guardrails/README.md`](./packages/openclaw-guardrails/README.md)
- Research report: [`docs/openclaw-llm-security-research.md`](./docs/openclaw-llm-security-research.md)
- RBAC research: [`docs/rbac-research.md`](./docs/rbac-research.md)

## Compatibility

- OpenClaw target: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`
