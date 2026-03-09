# RBAC Research Implementation

## Milestone 1: Immutable JSONL Audit Trail
- [x] Create `src/core/audit-sink.ts`
- [x] Add `audit` config to types.ts
- [x] Wire AuditSink into engine.ts
- [x] Add audit defaults to default-policy.ts + mergeConfig
- [x] Instantiate sink in openclaw-adapter.ts
- [x] Export from index.ts
- [x] Create test/audit-sink.test.ts

## Milestone 2: Custom Business Rule Validators
- [x] Create `src/core/custom-validator.ts`
- [x] Wire into engine.ts
- [x] Export from index.ts
- [x] Create test/custom-validator.test.ts

## Milestone 3: External Validator Integration
- [x] Create `src/core/detectors/external-validator-detector.ts`
- [x] Add config + reason codes to types.ts/reason-codes.ts
- [x] Export from detectors/index.ts, wire into engine.ts
- [x] Add defaults to default-policy.ts
- [x] Create test/external-validator.test.ts

## Milestone 4: Per-User Token Usage Tracking
- [x] Create `src/core/token-usage-store.ts`
- [x] Add config + types to types.ts
- [x] Wire into engine.ts + openclaw-adapter.ts
- [x] Add defaults to default-policy.ts
- [x] Create test/token-usage.test.ts

## Milestone 5: Admin Notification Bridge
- [x] Create `src/core/notification-sink.ts`
- [x] Add config to types.ts
- [x] Wire into approval.ts + openclaw-adapter.ts
- [x] Add defaults to default-policy.ts
- [x] Export from index.ts
- [x] Create test/notification-sink.test.ts

## Verification
- [x] `npx tsc --noEmit` -- no type errors
- [x] `npx vitest run` -- 86 tests pass (18 files)
- [x] `npx vitest run --coverage` -- 84.12% lines, 77.89% branches, 96.62% functions

## Milestone 6: Persistent RBAC Store with Dual-Authorization (v0.7.0)
- [x] SQLite-backed RoleStore with dual-auth (user RBAC ∩ bot capabilities)
- [x] Hash-chained audit log (separate SQLite DB)
- [x] ConfigRoleStore backward-compat adapter
- [x] Bot commands (`/sf`), HTTP admin API, and CLI
- [x] 144 tests across 20 test files, all passing

## Milestone 7: Runtime Policy Store & Zero-Config Bootstrap (v0.7.1)
- [x] Runtime policy store — 22 mutable config fields, persisted in SQLite
- [x] Zero-config bootstrap — `/sf setup` claims first ownership atomically
- [x] Dynamic RBAC role resolution — store-first lookup before config fallback
- [x] Atomic bootstrap with TOCTOU-safe SQLite transaction
- [x] `/sf policy` commands (list, show, get, set, reset)
- [x] Hot-path performance fixes, dead retry bug fix
- [x] 176 tests across 22 test files, all passing

---

## Milestone 8: SaaS Control Plane — Phase 0 (v0.8.0)
- [x] Add `ControlPlaneConfig` type to `src/core/types.ts`
- [x] Add `controlPlane?: ControlPlaneConfig` to `GuardrailsConfig`
- [x] Create `src/sync/types.ts` — shared protocol types
- [x] Default `controlPlane.enabled: false` in `default-policy.ts`

## Milestone 9: SaaS Control Plane — Phase 1 (v0.9.0)
- [x] `src/sync/http-client.ts` — typed REST client
- [x] `src/sync/sse-client.ts` — SSE client with auto-reconnect
- [x] `src/sync/policy-sync-loop.ts` — SSE-triggered policy pull
- [x] `src/sync/rbac-sync-loop.ts` — SSE-triggered RBAC pull
- [x] `src/sync/sync-role-store.ts` — wraps RoleStore + upstream sync
- [x] `src/sync/streaming-audit-sink.ts` — wraps AuditSink + batch upload
- [x] `src/sync/control-plane-agent.ts` — orchestrator
- [x] Integration in `openclaw-extension.ts`
- [x] Export new types/classes from `src/index.ts`

## Milestone 10: SaaS Control Plane — Phase 2 (v1.0.0)
- [x] `packages/control-plane/` scaffolding
- [x] DB schema + Drizzle models (orgs, instances, policies, RBAC, audit)
- [x] PostgreSQL migrations with RLS
- [x] Auth middleware (API key + JWT)
- [x] Sync API routes
- [x] Management API routes
- [x] Redis pub/sub for SSE broadcast
- [x] Audit ingest pipeline
- [x] `packages/dashboard/` Next.js skeleton
- [x] Docker Compose for local dev

### Verification
- [x] `npx tsc --noEmit` — zero type errors on guardrails package
- [x] `npx vitest run` — 186 tests pass across 22 files (no regressions)

---

## Milestone 11: Security Hardening (9 findings)

### Implementation
- [x] **M1**: .gitignore .env files
- [x] **H1**: Management API input validation (6 Zod schemas + parseBody)
- [x] **H3**: Cap legacy API key scan to 50 rows
- [x] **M2**: Security headers middleware (control-plane + Next.js)
- [x] **H2**: Redis sorted-set rate limiter (strict/moderate/relaxed tiers)
- [x] **M3**: Dashboard auth → sessionStorage
- [x] **M4**: Non-root Docker container (USER app)
- [x] **M5**: Redis authentication in docker-compose
- [x] **M6**: TLS enforcement option in http-client

### Verification
- [x] `pnpm --filter @safefence/types build` — compiles
- [x] `pnpm --filter @safefence/openclaw-guardrails build` — compiles
- [x] `pnpm --filter @safefence/control-plane build` — fixed ioredis imports + added @hono/node-server dep; builds clean
- [x] `pnpm --filter @safefence/dashboard build` — compiles, all pages generated
- [x] `pnpm --filter @safefence/openclaw-guardrails test` — 186 tests pass (22 files)
- [x] control-plane has no test files (server package, no vitest specs)
- [x] `git check-ignore .env` → `.env` (verified), `.env.example` NOT ignored
