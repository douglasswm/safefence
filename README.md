# SafeFence

[![npm version](https://img.shields.io/npm/v/@safefence/openclaw-guardrails)](https://www.npmjs.com/package/@safefence/openclaw-guardrails)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)
[![CI](https://github.com/douglasswm/safefence/actions/workflows/publish.yml/badge.svg)](https://github.com/douglasswm/safefence/actions/workflows/publish.yml)

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Deterministic security guardrails for OpenClaw AI agents. A 12-detector pipeline that evaluates every agent action locally in sub-millisecond time -- no remote inference, no runtime dependencies. Optionally connects to a centralized control plane for multi-instance policy sync and audit aggregation.

## Architecture

```mermaid
graph TB
    subgraph Cloud ["SafeFence Cloud (optional)"]
        CP["control-plane<br/>Hono REST API<br/>:3100"]
        PG[("PostgreSQL 16")]
        RD[("Redis 7")]
        DASH["dashboard<br/>Next.js UI<br/>:3200"]
        CP --- PG
        CP --- RD
        DASH -->|"proxy → X-API-Key"| CP
    end

    subgraph Instance1 ["OpenClaw Instance"]
        GE1["@safefence/openclaw-guardrails<br/>─────────────────────────<br/>GuardrailsEngine · 12 detectors<br/>Dual-auth RBAC · Policy store<br/>Audit trail · Approvals"]
    end

    subgraph Instance2 ["OpenClaw Instance"]
        GE2["@safefence/openclaw-guardrails"]
    end

    CP -->|"SSE: policy_changed<br/>rbac_changed"| Instance1
    Instance1 -->|"REST: audit batch<br/>heartbeat · ack"| CP
    CP -->|"SSE + REST"| Instance2
    Instance2 -->|"REST"| CP
```

**Two deployment modes:**

- **Standalone** -- Install the plugin, configure policies in code, done. Zero infrastructure. This is the default.
- **Cloud** -- Add a control plane server to centrally manage policies, RBAC, and audit across multiple OpenClaw instances. Detectors still run locally; the control plane is never in the hot path.

**Two deployment modes:**

- **Standalone** -- Install the plugin, configure policies in code, done. Zero infrastructure. This is the default.
- **Cloud** -- Add a control plane server to centrally manage policies, RBAC, and audit across multiple OpenClaw instances. Detectors still run locally; the control plane is never in the hot path.

## Packages

This is a pnpm workspace. All packages are managed from the repository root.

| Package | Description | Status | Docs |
|---------|-------------|--------|------|
| [`@safefence/types`](./packages/types/) | Shared protocol-boundary types | **Stable** | [README](./packages/types/README.md) |
| [`@safefence/openclaw-guardrails`](./packages/openclaw-guardrails/) | Core guardrails plugin for OpenClaw | **Production-ready** -- 186 tests, ~85% coverage | [README](./packages/openclaw-guardrails/README.md) · [Architecture](./packages/openclaw-guardrails/docs/ARCHITECTURE.md) · [Config](./packages/openclaw-guardrails/docs/CONFIG.md) |
| [`@safefence/control-plane`](./packages/control-plane/) | Centralized REST API (Hono + PostgreSQL + Redis) | **Functional** -- builds clean, no tests yet | [README](./packages/control-plane/README.md) |
| [`@safefence/dashboard`](./packages/dashboard/) | Next.js admin UI | **Scaffold** -- working proxy and API integration | [README](./packages/dashboard/README.md) |

## Quick Start: Standalone

```bash
pnpm install          # from repo root — installs all workspace packages
pnpm --filter @safefence/openclaw-guardrails test    # 186 tests
pnpm --filter @safefence/openclaw-guardrails build   # produces dist/
```

Configure in your `openclaw.config.ts` and you're running. See the [plugin README](./packages/openclaw-guardrails/README.md) for full configuration.

## Quick Start: Cloud

```bash
# 1. Start infrastructure
cd packages/control-plane
docker compose up -d

# 2. Push database schema
npx drizzle-kit push

# 3. Create an organization (returns an API key)
curl -s -X POST http://localhost:3100/api/v1/orgs \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Org"}' | jq .

# 4. Configure plugin instances to sync
#    In openclaw.config.ts, add:
#      controlPlane: {
#        enabled: true,
#        endpoint: "http://localhost:3100",
#        orgApiKey: "sf_..."
#      }

# 5. Start the dashboard (scaffold -- read-only placeholder UI)
pnpm --filter @safefence/dashboard dev
# → http://localhost:3200
```

For the full step-by-step guide, environment variable reference, and current limitations, see **[docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md)**.

## Documentation

| Document | Contents |
|----------|----------|
| [Plugin README](./packages/openclaw-guardrails/README.md) | Installation, configuration, bot commands, admin API |
| [Architecture](./packages/openclaw-guardrails/docs/ARCHITECTURE.md) | Detector pipeline, approval workflow, sequence diagrams |
| [Config Reference](./packages/openclaw-guardrails/docs/CONFIG.md) | All configuration fields including control plane options |
| [Migration Guide](./packages/openclaw-guardrails/docs/MIGRATION.md) | Version upgrade notes (v0.5 → v0.8) |
| [Deployment Guide](./docs/DEPLOYMENT.md) | Standalone & cloud setup, env vars, limitations |
| [LLM Security Research](./docs/openclaw-llm-security-research.md) | OWASP mapping, threat model, hardening guidance |
| [RBAC Research](./docs/rbac-research.md) | RBAC and adaptive guardrails strategic framework |

## Security

The security hardening across the control plane and dashboard includes:

| Feature | Where |
|---------|-------|
| Input validation (Zod schemas on all endpoints) | control-plane management + sync API |
| Rate limiting (3 tiers: 10/100/600 req/min, Redis sliding window) | control-plane |
| Security headers (HSTS, X-Frame-Options, nosniff, Referrer-Policy) | control-plane + dashboard |
| O(1) API key lookup via prefix column + bcrypt verify | control-plane |
| Bootstrap secret gate for org creation | control-plane |
| Non-root Docker container | control-plane |
| Redis authentication | control-plane |
| TLS enforcement for non-localhost control plane connections | guardrails agent |
| Path traversal prevention in dashboard proxy | dashboard |
| CSP headers | dashboard |

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for the full security reference.

## Compatibility

- OpenClaw: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`

## Release Workflow

Releases are published automatically via GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). Every published version includes a Sigstore-signed attestation linking the package to the exact source commit and CI workflow.

```bash
# 1. Bump version from the package directory
cd packages/openclaw-guardrails
pnpm version patch   # or: minor | major

# 2. pnpm version updates package.json, but the version sync script
#    also modifies openclaw.plugin.json, version.ts, and the root
#    README.md. These changes are staged but NOT committed
#    automatically -- commit them yourself:
cd ../..
git add -A
git commit -m "chore: bump version to $(node -p "require('./packages/openclaw-guardrails/package.json').version")"

# 3. Tag and push -- the v* tag triggers CI to publish to npm
git tag "v$(node -p "require('./packages/openclaw-guardrails/package.json').version")"
git push origin master --tags

# 4. Verify provenance after CI completes
npm audit signatures
```

`pnpm version` must be run from `packages/openclaw-guardrails/` because it operates on that directory's `package.json`. It runs tests and builds via `preversion`, then syncs the version to `openclaw.plugin.json`, `src/plugin/version.ts`, and the root `README.md` via `scripts/sync-version.sh`. However, because this is a monorepo subdirectory, pnpm's auto-commit does not reliably capture all synced files -- you must commit and tag manually.
