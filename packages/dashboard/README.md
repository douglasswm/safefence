# @safefence/dashboard

Next.js 15 admin dashboard for SafeFence. Provides a web UI for managing policies, RBAC, instances, and audit logs via the control plane API.

**Status: Scaffold** — all five pages are functional with live data via the server-side proxy. Auth and API integration work; data shapes reflect the actual control plane responses.

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Overview | Connected instance count, total evaluations, denied/allowed stats |
| `/instances` | Instances | Fleet view with status, version, heartbeat, policy/RBAC version |
| `/policies` | Policies | Full CRUD — create, edit (JSON), delete, version history |
| `/rbac` | RBAC | Role management and user/role assignment |
| `/audit` | Audit Log | Event list with client-side filtering by type and instance |

## Architecture

```
Browser
  │
  │  sessionStorage: { orgId, apiKey }
  │
  ▼
Next.js App (port 3200)
  │
  ├── /app/*          Client components (React, inline styles)
  │
  └── /api/proxy/[...path]   Server-side catch-all proxy
          │
          │  Validates Authorization header
          │  Sanitizes path (strips ../ traversal)
          │  Forwards Content-Type + Authorization
          │
          ▼
      Control Plane API (port 3100)
          /api/v1/orgs/:orgId/*
```

All API traffic flows through the server-side proxy to avoid CORS. The browser never makes direct requests to the control plane.

## Security

| Feature | Implementation |
|---------|---------------|
| Security headers | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Referrer-Policy`, `X-XSS-Protection: 0` applied via `next.config.ts` |
| CSP | `default-src 'self'` with restricted `connect-src`; `unsafe-inline`/`unsafe-eval` in `script-src` for Next.js compatibility |
| Credentials | Stored in `sessionStorage` (cleared on tab close); never sent to any origin except the same-origin proxy |
| Path traversal | Proxy strips `..` and `.` path segments and `encodeURIComponent`s each segment before forwarding |
| Auth forwarding | Proxy requires `Authorization` header; rejects with 401 if missing |

## Quick start

```bash
# From repo root
cd packages/control-plane
docker compose up -d

# In another terminal
pnpm --filter @safefence/dashboard dev
# → http://localhost:3200
```

Log in with your org ID and API key (`sf_...` from org creation).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTROL_PLANE_URL` | `http://localhost:3100` | Control plane base URL (server-side only) |

Set via environment variable or `.env.local`. The dashboard dev server runs on port 3200 (configured in `package.json`).

## Development

```bash
pnpm --filter @safefence/dashboard dev     # dev server
pnpm --filter @safefence/dashboard build   # production build
pnpm --filter @safefence/dashboard start   # production server
```

TypeScript path alias `@/*` maps to `./src/*`.
