# Deployment Guide

## Standalone Mode (Plugin Only)

The default mode. No infrastructure required -- the plugin runs entirely within your OpenClaw instance using local SQLite for persistence.

**What you get:** 12-detector pipeline, dual-auth RBAC, policy store, audit trail, approval workflow, bot commands.

**What you don't get:** Centralized management, cross-instance policy sync, aggregated audit view.

### Setup

```bash
pnpm install                                          # from repo root
pnpm --filter @safefence/openclaw-guardrails build    # produces dist/
```

Configure the plugin in your `openclaw.config.ts` -- see the [Config Reference](../packages/openclaw-guardrails/docs/CONFIG.md) for all options.

On first run, use `/sf setup` in any channel to claim ownership. This bootstraps the RBAC store without requiring config file edits.

---

## Cloud Mode (Control Plane + Instances)

Adds centralized policy, RBAC, and audit management across multiple OpenClaw instances. Each instance syncs via SSE + REST while continuing to evaluate all detectors locally.

### Prerequisites

- Docker and Docker Compose
- Node.js >= 20
- The guardrails plugin already installed and working in standalone mode

### Step 1: Start Infrastructure

```bash
cd packages/control-plane
docker compose up -d
```

This starts three services:

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL 16 | 5432 | Primary data store (policies, RBAC, audit, instances) |
| Redis 7 | 6379 | Pub/sub for SSE broadcast to connected instances |
| Control Plane API | 3100 | Hono REST API for sync and management |

### Step 2: Run Database Migrations

With infrastructure running:

```bash
cd packages/control-plane
npx drizzle-kit push
```

This pushes the Drizzle schema directly to PostgreSQL. For production, use `npx drizzle-kit generate` + `npx drizzle-kit migrate` instead for versioned migration files.

### Step 3: Create an Organization

```bash
curl -s -X POST http://localhost:3100/api/v1/orgs \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Org"}' | jq .
```

Response includes an API key (`sf_...`). **Save this key** -- it authenticates all management API calls and plugin instance registrations.

### Step 4: Configure Plugin Instances

In each OpenClaw instance's `openclaw.config.ts`, add the `controlPlane` block:

```typescript
controlPlane: {
  enabled: true,
  endpoint: "http://localhost:3100",
  orgApiKey: "sf_..."   // from Step 3
}
```

When `controlPlane.enabled` is `true`, the plugin will:
- Register with the control plane on startup
- Send heartbeats periodically
- Pull policy and RBAC updates via SSE-triggered REST calls
- Upload audit events in batches
- Fall back to cached local state if disconnected

### Step 5: Verify

Check that the instance registered:

```bash
# Get your org ID from the org creation response, then:
curl -s http://localhost:3100/api/v1/orgs/<orgId>/instances \
  -H 'X-API-Key: sf_...' | jq .
```

You should see your instance listed with a recent `lastHeartbeat` timestamp.

Health check:

```bash
curl http://localhost:3100/health
```

### Step 6: Manage via API

All management endpoints require the org API key in the `X-API-Key` header.

**Policy management:**

```bash
# List policies
curl -s http://localhost:3100/api/v1/orgs/<orgId>/policies \
  -H 'X-API-Key: sf_...' | jq .

# Set a policy
curl -s -X PUT http://localhost:3100/api/v1/orgs/<orgId>/policies/maxInputLength \
  -H 'X-API-Key: sf_...' \
  -H 'Content-Type: application/json' \
  -d '{"value": 10000}' | jq .

# Delete a policy (reverts to default)
curl -s -X DELETE http://localhost:3100/api/v1/orgs/<orgId>/policies/maxInputLength \
  -H 'X-API-Key: sf_...'
```

**RBAC management:**

```bash
# Create a role
curl -s -X POST http://localhost:3100/api/v1/orgs/<orgId>/roles \
  -H 'X-API-Key: sf_...' \
  -H 'Content-Type: application/json' \
  -d '{"name": "developer", "permissions": ["tool:read", "tool:execute"]}' | jq .

# List roles
curl -s http://localhost:3100/api/v1/orgs/<orgId>/roles \
  -H 'X-API-Key: sf_...' | jq .

# Assign a role to a user
curl -s -X POST http://localhost:3100/api/v1/orgs/<orgId>/users/<userId>/roles \
  -H 'X-API-Key: sf_...' \
  -H 'Content-Type: application/json' \
  -d '{"roleId": "..."}' | jq .
```

**Audit:**

```bash
# Query audit events
curl -s http://localhost:3100/api/v1/orgs/<orgId>/audit \
  -H 'X-API-Key: sf_...' | jq .

# Audit stats
curl -s http://localhost:3100/api/v1/orgs/<orgId>/audit/stats \
  -H 'X-API-Key: sf_...' | jq .
```

---

## Dashboard

The dashboard is a Next.js application with five pages: overview, instances, policies, RBAC, and audit. All pages display live data via a server-side proxy to the control plane.

To run it:

```bash
pnpm --filter @safefence/dashboard dev
# → http://localhost:3200
```

Log in with your org ID and API key (`sf_...`) from Step 3. See [packages/dashboard/README.md](../packages/dashboard/README.md) for details.

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `JWT_SECRET` | — | **Yes** | HMAC-SHA256 secret for instance JWT tokens. Server will not start without it. **Change in production.** |
| `DATABASE_URL` | `postgres://user:password@localhost:5432/safefence` | Yes (prod) | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | No | Redis connection for rate limiting and SSE pub/sub |
| `REDIS_PASSWORD` | `safefence-dev` | No | Redis auth password (keep in sync with `REDIS_URL`) |
| `PORT` | `3100` | No | Control plane HTTP server port |
| `CORS_ORIGIN` | `http://localhost:3200` | No | Allowed CORS origin (dashboard URL) |
| `BOOTSTRAP_SECRET` | — | No | If set, org creation requires matching `X-Bootstrap-Secret` header |

A `.env.example` template is provided at `packages/control-plane/.env.example`. The `docker-compose.yml` sets all variables automatically for local development. For production, inject them via your deployment platform's secrets management.

---

## Security

### Rate Limiting

Redis-backed sliding window rate limiter with three tiers (most-specific first):

| Tier | Path | Limit | Identifier |
|------|------|-------|------------|
| Public | `POST /api/v1/orgs` | 10 req/min | IP address |
| Management | `/api/v1/*` | 100 req/min | org ID (or IP) |
| Sync | `/api/v1/sync/*` | 600 req/min | org ID (or IP) |

Rejected requests return `429` with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` response headers.

### Security Headers

All responses include:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `X-XSS-Protection` | `0` |

### Input Validation

All management and sync endpoints validate request bodies via Zod schemas. Invalid payloads return `400` with structured error details listing each failing field.

### API Key Authentication

Org API keys are bcrypt-hashed. An 8-character prefix column enables O(1) row lookup before bcrypt verification, keeping authentication fast even at scale.

### Bootstrap Secret

Set `BOOTSTRAP_SECRET` to gate org creation in production. Without a valid `X-Bootstrap-Secret` header, `POST /api/v1/orgs` returns `403`.

### TLS Enforcement (Agent Side)

The guardrails agent enforces HTTPS for all non-localhost control plane connections by default (`requireTls: true` in production). Override with `requireTls: false` for development tunnels. See the [Config Reference](../packages/openclaw-guardrails/docs/CONFIG.md) for the `controlPlane.requireTls` option.

### Container Security

The control plane Docker image runs as a non-root `app` user. Base image: `node:22-alpine`.

### Redis Authentication

Redis starts with a password in docker-compose. Set `REDIS_PASSWORD` and include it in `REDIS_URL` (e.g., `redis://:password@localhost:6379`).

---

## Current Limitations

- **Mutation sync is advisory** -- when instances push local mutations (e.g., `/sf policy set`), the server currently discards them. Cloud-wins semantics; local mutations are not persisted centrally.
- **JWT tokens expire in 24h with no refresh** -- instance tokens are issued with a hardcoded 24-hour expiry (`HS256`). There is no token refresh mechanism; instances must re-register after expiry.
- **RBAC delta sync falls back to full snapshot** -- the sync protocol supports delta pulls, but the current implementation always sends the full RBAC state.

---

## Sync Protocol Flow

```mermaid
sequenceDiagram
    participant A as Guardrails Agent
    participant CP as Control Plane
    participant PG as PostgreSQL
    participant RD as Redis

    A->>CP: POST /sync/register (orgApiKey, instanceId)
    CP->>PG: insert/update instance, check org membership
    CP-->>A: { jwt, policyVersion, rbacVersion }

    A->>CP: GET /sync/events (SSE, Bearer jwt)
    Note over A,CP: Long-lived SSE connection

    Note over CP,RD: Admin sets policy via dashboard
    CP->>PG: upsert policy_current, bump org_versions
    CP->>RD: PUBLISH safefence:sync:{orgId} policy_changed
    RD-->>CP: broadcast to SSE connections
    CP-->>A: event: policy_changed { version: N }

    A->>CP: GET /sync/policies?since=N (Bearer jwt)
    CP->>PG: select policies updated after version N
    CP-->>A: [{ key, value, scope, version }]

    A->>CP: POST /sync/ack { policyVersion: N }
    CP->>PG: update instance.policy_version = N

    loop Every 5 seconds
        A->>CP: POST /sync/audit/batch { events[], cursor }
        CP->>PG: insert audit_events (server-generated IDs)
        CP-->>A: { accepted, cursor }
    end

    loop Every 60 seconds
        A->>CP: POST /sync/heartbeat { policyVersion, rbacVersion }
        CP->>PG: update instance.last_heartbeat_at
        CP-->>A: { stale: false }
    end
```

## Instance Lifecycle

```mermaid
stateDiagram-v2
    [*] --> registered : POST /sync/register
    registered --> active : first heartbeat received
    active --> connected : SSE connection established
    connected --> active : SSE disconnected (still heartbeating)
    active --> disconnected : POST /sync/deregister
    connected --> disconnected : POST /sync/deregister
    active --> stale : heartbeat timeout (no heartbeat for threshold)
    connected --> stale : heartbeat timeout
    stale --> active : heartbeat resumes
    disconnected --> registered : re-register (same instanceId)
    disconnected --> deregistered : admin DELETE /instances/:id
    stale --> deregistered : admin DELETE /instances/:id
```

---

## API Reference

### Sync API (Instance-facing)

Used by plugin instances. Authenticated via instance JWT (obtained during registration).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/sync/register` | Register instance (uses org API key) |
| POST | `/api/v1/sync/heartbeat` | Instance heartbeat |
| POST | `/api/v1/sync/deregister` | Deregister instance |
| GET | `/api/v1/sync/events` | SSE event stream (policy/RBAC change notifications) |
| GET | `/api/v1/sync/policies` | Pull current policies |
| GET | `/api/v1/sync/rbac` | Pull current RBAC state |
| POST | `/api/v1/sync/audit/batch` | Upload audit events (batched) |
| POST | `/api/v1/sync/mutations` | Push local mutations (advisory) |
| POST | `/api/v1/sync/ack` | Acknowledge sync cursor |

### Management API (Admin-facing)

Used by dashboards and admin tools. Authenticated via org API key in `X-API-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/orgs` | Create organization (unauthenticated) |
| GET | `/api/v1/orgs/:orgId/instances` | List registered instances |
| DELETE | `/api/v1/orgs/:orgId/instances/:id` | Remove an instance |
| POST | `/api/v1/orgs/:orgId/groups` | Create instance group |
| GET | `/api/v1/orgs/:orgId/groups` | List instance groups |
| GET | `/api/v1/orgs/:orgId/policies` | List policies |
| PUT | `/api/v1/orgs/:orgId/policies/:key` | Set a policy value |
| DELETE | `/api/v1/orgs/:orgId/policies/:key` | Delete a policy (revert to default) |
| GET | `/api/v1/orgs/:orgId/policies/versions` | Policy version history |
| POST | `/api/v1/orgs/:orgId/roles` | Create a role |
| GET | `/api/v1/orgs/:orgId/roles` | List roles |
| DELETE | `/api/v1/orgs/:orgId/roles/:roleId` | Delete a role |
| POST | `/api/v1/orgs/:orgId/users` | Create a user |
| GET | `/api/v1/orgs/:orgId/users` | List users |
| POST | `/api/v1/orgs/:orgId/users/:userId/roles` | Assign role to user |
| GET | `/api/v1/orgs/:orgId/audit` | Query audit events |
| GET | `/api/v1/orgs/:orgId/audit/stats` | Audit statistics |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health check (unauthenticated) |
