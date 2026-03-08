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
