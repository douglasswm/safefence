# @safefence/control-plane

Centralized management server for SafeFence. A Hono REST API backed by PostgreSQL and Redis that handles multi-instance policy sync, RBAC management, audit aggregation, and real-time SSE broadcasting to connected guardrail agents.

## Architecture

```mermaid
graph TB
    subgraph "Docker Compose"
        CP["control-plane<br/>Hono REST API<br/>:3100"]
        PG["PostgreSQL 16<br/>:5432"]
        RD["Redis 7<br/>:6379"]
        CP -->|Drizzle ORM| PG
        CP -->|ioredis| RD
    end

    subgraph "Clients"
        DASH["Dashboard<br/>:3200"]
        A1["Agent Instance 1"]
        A2["Agent Instance 2"]
    end

    DASH -->|X-API-Key<br/>Management API| CP
    A1 -->|Instance JWT<br/>Sync API + SSE| CP
    A2 -->|Instance JWT<br/>Sync API + SSE| CP
    RD -->|pub/sub broadcast| CP
```

**Two auth modes:**
- **Management API** (`/api/v1/orgs/*`) — org API key in `X-API-Key` header, for dashboards and admin tools
- **Sync API** (`/api/v1/sync/*`) — instance JWT (HS256, 24h) obtained during registration, for guardrail agents

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# Set JWT_SECRET to a strong random value

# 2. Start infrastructure
docker compose up -d

# 3. Push database schema
npx drizzle-kit push

# 4. Create an organization (returns API key sf_...)
curl -s -X POST http://localhost:3100/api/v1/orgs \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Org"}' | jq .

# 5. Verify
curl http://localhost:3100/health
```

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `JWT_SECRET` | — | **Yes** | HMAC-SHA256 secret for instance JWT tokens. Server exits on startup if unset. |
| `DATABASE_URL` | `postgres://user:password@localhost:5432/safefence` | Yes (prod) | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | No | Redis connection for rate limiting and SSE pub/sub |
| `REDIS_PASSWORD` | `safefence-dev` | No | Redis auth password (keep in sync with `REDIS_URL`) |
| `PORT` | `3100` | No | HTTP server port |
| `CORS_ORIGIN` | `http://localhost:3200` | No | Allowed CORS origin (dashboard URL) |
| `BOOTSTRAP_SECRET` | — | No | If set, org creation requires matching `X-Bootstrap-Secret` header |

See `.env.example` for the full template.

## Security

### Input Validation

All management endpoints validate request bodies via Zod schemas before touching the database. Invalid payloads return `400` with structured error details. Key schemas:

- `createOrgSchema` — org name + plan tier
- `upsertPolicySchema` — policy value (any JSON) + optional scope/updatedBy
- `createRoleSchema` — role name + optional description/projectId
- `createUserSchema` — display name + optional platform identity
- `createAssignmentSchema` — role ID + scope type/ID + optional expiry

### Rate Limiting

Redis-backed sliding window rate limiter. Three tiers applied most-specific-first:

| Tier | Path Pattern | Limit | Key Prefix |
|------|-------------|-------|-----------|
| Sync | `/api/v1/sync/*` | 600 req/min | `rl:sync` |
| Management | `/api/v1/*` | 100 req/min | `rl:mgmt` |
| Public (org creation) | `/api/v1/orgs` | 10 req/min | `rl:pub` |

Rejected requests receive `429` with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers. Admitted requests always include the limit/remaining/reset headers.

**Identifier resolution:** Uses `orgId` from auth context when available; falls back to `X-Forwarded-For` first IP, then `"unknown"`.

```mermaid
flowchart LR
    REQ[Request] --> PRUNE[ZREMRANGEBYSCORE\nprune expired]
    PRUNE --> COUNT[ZCARD\ncount window]
    COUNT --> CHECK{count >= limit?}
    CHECK -->|Yes| REJECT[429 + headers]
    CHECK -->|No| ADMIT[ZADD + EXPIRE\nadd to window]
    ADMIT --> NEXT[next middleware]
```

### Security Headers

Applied globally after every response:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `X-XSS-Protection` | `0` (disabled per modern best practice) |

### API Key Authentication

Org API keys are stored hashed (bcrypt). Lookup uses an O(1) fast path via an 8-character `api_key_prefix` column: the prefix identifies the target row, then bcrypt verifies the full key. Legacy orgs without a prefix fall back to a capped sequential scan (max 50).

### Bootstrap Secret

If `BOOTSTRAP_SECRET` is set, `POST /api/v1/orgs` requires a matching `X-Bootstrap-Secret` header. Without it, org creation returns `403`. Leave unset for development.

### Container Security

The Docker image runs as a non-root `app` user (created in the Dockerfile's runtime stage). Base image is `node:22-alpine`.

### Redis Authentication

Redis is started with a password in docker-compose. The control plane connects via `REDIS_URL` which includes the password. Set `REDIS_PASSWORD` to the same value.

## API Reference

### Sync API (Instance-facing)

Authenticated via instance JWT in `Authorization: Bearer <token>` header. JWT obtained from `/api/v1/sync/register`.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/sync/register` | Register instance (uses org API key in body); returns JWT + version cursors |
| POST | `/api/v1/sync/heartbeat` | Instance heartbeat + version ack |
| POST | `/api/v1/sync/deregister` | Mark instance disconnected |
| GET | `/api/v1/sync/events` | SSE event stream (`policy_changed`, `rbac_changed`, `force_resync`, `revoked`) |
| GET | `/api/v1/sync/policies` | Pull current policies; `?since=N` for delta |
| GET | `/api/v1/sync/rbac` | Pull full RBAC snapshot |
| POST | `/api/v1/sync/audit/batch` | Upload audit events (max 1000 per batch) |
| POST | `/api/v1/sync/mutations` | Push local mutations (advisory; cloud-wins) |
| POST | `/api/v1/sync/ack` | Acknowledge policy/RBAC version sync |

### Management API (Admin-facing)

Authenticated via `X-API-Key: sf_...` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/orgs` | Create organization; returns API key |
| GET | `/api/v1/orgs/:orgId/instances` | List registered instances |
| DELETE | `/api/v1/orgs/:orgId/instances/:id` | Remove instance + broadcast revocation |
| POST | `/api/v1/orgs/:orgId/groups` | Create instance group |
| GET | `/api/v1/orgs/:orgId/groups` | List instance groups |
| GET | `/api/v1/orgs/:orgId/policies` | List current policies |
| GET | `/api/v1/orgs/:orgId/policies/versions` | Policy version history (last 100) |
| PUT | `/api/v1/orgs/:orgId/policies/:key` | Upsert policy (transactional, versioned) |
| DELETE | `/api/v1/orgs/:orgId/policies/:key` | Delete policy |
| POST | `/api/v1/orgs/:orgId/roles` | Create RBAC role |
| GET | `/api/v1/orgs/:orgId/roles` | List roles |
| DELETE | `/api/v1/orgs/:orgId/roles/:roleId` | Delete role |
| POST | `/api/v1/orgs/:orgId/users` | Create user + optional platform identity |
| GET | `/api/v1/orgs/:orgId/users` | List users |
| POST | `/api/v1/orgs/:orgId/users/:userId/roles` | Assign role to user |
| GET | `/api/v1/orgs/:orgId/audit` | Query audit events (`?limit=`, `?since=`) |
| GET | `/api/v1/orgs/:orgId/audit/stats` | Aggregate audit stats |

### Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Server health check |

## Database Schema

```mermaid
erDiagram
    organizations {
        text id PK
        text name
        text api_key_hash
        text api_key_prefix
        text plan_tier
        int max_instances
        int max_audit_retention_days
        timestamp created_at
    }
    instance_groups {
        text id PK
        text org_id FK
        text name
        text description
        timestamp created_at
    }
    instances {
        text id PK
        text org_id FK
        text group_id FK
        text status
        text plugin_version
        jsonb tags
        int policy_version
        int rbac_version
        bigint audit_cursor
        timestamp last_heartbeat_at
        jsonb last_metrics
        timestamp created_at
    }
    policy_current {
        text id PK
        text org_id FK
        text key
        jsonb value
        text scope
        text scope_id
        int version
        timestamp updated_at
    }
    policy_versions {
        text id PK
        text org_id FK
        text policy_id FK
        text key
        jsonb value
        text scope
        text scope_id
        int version
        text changed_by
        timestamp created_at
    }
    cloud_roles {
        text id PK
        text org_id FK
        text project_id
        text name
        boolean is_system
        timestamp created_at
    }
    cloud_users {
        text id PK
        text org_id FK
        text display_name
        timestamp created_at
    }
    cloud_role_assignments {
        text id PK
        text org_id FK
        text user_id FK
        text role_id FK
        text scope_type
        text scope_id
        timestamp expires_at
        timestamp created_at
    }
    audit_events {
        text id PK
        text org_id FK
        text instance_id
        bigint seq
        timestamp timestamp
        text event_type
        text decision
        text denied_by
        text prev_hash
        text event_hash
    }
    org_versions {
        text org_id PK
        int policy_version
        int rbac_version
    }

    organizations ||--o{ instance_groups : "org_id"
    organizations ||--o{ instances : "org_id"
    instance_groups ||--o{ instances : "group_id"
    organizations ||--o{ policy_current : "org_id"
    policy_current ||--o{ policy_versions : "policy_id"
    organizations ||--o{ cloud_roles : "org_id"
    organizations ||--o{ cloud_users : "org_id"
    cloud_users ||--o{ cloud_role_assignments : "user_id"
    cloud_roles ||--o{ cloud_role_assignments : "role_id"
    organizations ||--o{ audit_events : "org_id"
    organizations ||--|| org_versions : "org_id"
```

## Development Commands

```bash
# Install all workspace dependencies (from repo root)
pnpm install

# Start infrastructure
docker compose up -d

# Push schema to local DB
npx drizzle-kit push

# Dev server with hot reload
pnpm dev

# Type-check + compile
pnpm build

# Generate migration files (for production)
npx drizzle-kit generate
npx drizzle-kit migrate
```
