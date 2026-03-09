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

## Dashboard (Status: Scaffold)

The dashboard is a Next.js application that provides a UI shell with five pages: overview, instances, policies, RBAC, and audit.

**Important:** The dashboard currently has **no API integration**. All pages display hardcoded placeholder content. It is a static scaffold intended for future development.

To run it:

```bash
pnpm --filter @safefence/dashboard dev
# → http://localhost:3200
```

You'll see the UI layout, but no live data from the control plane.

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PORT` | `3100` | No | Control plane HTTP server port |
| `DATABASE_URL` | `postgresql://localhost:5432/safefence` | Yes (production) | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | Yes (production) | Redis connection for SSE pub/sub |
| `JWT_SECRET` | `safefence-dev-secret-change-in-production` | **Yes** | HMAC secret for instance JWT tokens. **Change this in production.** |

The `docker-compose.yml` sets these automatically for local development. For production, set them as real environment variables or via your deployment platform's secrets management.

There are currently no `.env.example` files in the repository.

---

## Current Limitations

- **Dashboard has no API integration** -- all five pages are static scaffolds with hardcoded placeholder data. The architecture diagram shows "Dashboard <-> REST API" but this connection does not exist in code yet.
- **Mutation sync is advisory** -- when instances push local mutations (e.g., `/sf policy set`), the server currently discards them. Cloud-wins semantics; local mutations are not persisted centrally.
- **JWT tokens expire in 24h with no refresh** -- instance tokens are issued on registration with a hardcoded 24-hour expiry (`HS256`). There is no token refresh mechanism; instances must re-register after expiry.
- **API key lookup is O(n) bcrypt** -- org API key verification iterates all keys and runs bcrypt comparison on each. This is fine for small deployments but does not scale. A prefix-based lookup column is planned.
- **RBAC delta sync falls back to full snapshot** -- the sync protocol supports delta pulls, but the current implementation always sends the full RBAC state.
- **No `.env.example` files** -- environment variable documentation exists only in this guide and in `docker-compose.yml`.

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
