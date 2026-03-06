# SafeFence

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Security-focused tooling for hardening OpenClaw agent deployments, with emphasis on OWASP LLM Top 10 controls, deterministic guardrails, and multi-user safety.

## Repository Layout

- `packages/openclaw-guardrails`: production TypeScript guardrails library/plugin.
- `docs/openclaw-llm-security-research.md`: threat research, OWASP mapping, and hardening guidance.
- `docs/rbac-research.md`: RBAC and adaptive guardrails strategic framework.
- `CLAUDE.md`: local engineering workflow and coding standards.

## What This Project Delivers

A deterministic security plugin for OpenClaw agents — no remote inference, zero runtime dependencies. Current version: `0.6.0`.

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
- 88 tests across 18 test files at ~85% line coverage.

## Quick Start (Current Package)

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```

## Publish the OpenClaw Plugin (npm)

```bash
cd packages/openclaw-guardrails

# Pre-publish
npm whoami && npm test && npm run build
npm pack --dry-run --cache ./.npm-cache

# Publish (use --tag beta for prereleases)
npm publish --access public

# Verify
npm view @safefence/openclaw-guardrails version
openclaw plugins install @safefence/openclaw-guardrails@<version>
openclaw plugins list
```

Ensure `package.json` has `openclaw.extensions` pointing to `./dist/plugin/openclaw-extension.js`, and the tarball includes `dist/**`, `openclaw.plugin.json`, and `README.md`.

## Documentation

- Package docs: [`packages/openclaw-guardrails/README.md`](./packages/openclaw-guardrails/README.md)
- Research report: [`docs/openclaw-llm-security-research.md`](./docs/openclaw-llm-security-research.md)
- RBAC research: [`docs/rbac-research.md`](./docs/rbac-research.md)

## Compatibility

- OpenClaw target: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`
