# SafeFence: Persistent RBAC Store with Dual-Authorization Model

## Phase 1: Data Model + RoleStore Interface
- [x] 1.1 Add new types to `src/core/types.ts`
- [x] 1.2 Add new reason codes to `src/core/reason-codes.ts`
- [x] 1.3 Create `src/core/role-store.ts` (RoleStore interface)
- [x] 1.4 Create `src/core/config-role-store.ts` (backward compat adapter)
- [x] 1.5 Create `src/core/audit-store.ts` (hash-chained, tamper-evident)
- [x] 1.6 Create `src/core/sqlite-role-store.ts` (SQLite + schema + seeding + dual-auth)
- [x] 1.7 identity.ts unchanged (principal-authz-detector handles RoleStore integration)
- [x] 1.8 authorization.ts unchanged (still used as fallback; dual-auth in detector)
- [x] 1.9 Modify `src/core/engine.ts` — accept RoleStore in EngineOptions
- [x] 1.10 Modify `src/core/detectors/principal-authz-detector.ts` — dual-auth with store
- [x] 1.11 Modify `src/core/audit-sink.ts` — enrich with bot_instance_id
- [x] 1.12 Modify `src/plugin/openclaw-adapter.ts` — wire store to engine
- [x] 1.13 Modify `src/plugin/openclaw-extension.ts` — initialize store from config
- [x] 1.14 Modify `src/rules/default-policy.ts` — default rbacStore config
- [x] 1.15 Modify `src/index.ts` — export new types
- [x] 1.16 Modify `package.json` — add better-sqlite3 peer dep, bin entry
- [x] 1.17 Create `test/role-store.test.ts` — 32 tests (store + dual-auth + audit)
- [x] 1.18 All 144 tests pass (112 existing + 32 new)

## Phase 2: Bot Commands
- [x] 2.1 /sf role commands (create, delete, list, permissions, grant-perm, revoke-perm)
- [x] 2.2 /sf assign and /sf revoke commands
- [x] 2.3 /sf who command
- [x] 2.4 /sf bot commands (register, cap set/list, access, list)
- [x] 2.5 /sf channel commands (link, unlink)
- [x] 2.6 /sf audit commands

## Phase 3: HTTP Admin API
- [x] 3.1 Create `src/admin/server.ts` — lightweight HTTP server
- [x] 3.2 Create `src/admin/routes.ts` — REST handlers (all endpoints implemented)

## Phase 4: CLI Tool
- [x] 4.1 Create `src/cli/index.ts` — CLI tool
- [x] 4.2 bin/safefence entry point in package.json

## Phase 5: Testing & Verification
- [x] 5.1 Dual-auth scenario tests (8 tests covering intersection, deny-overrides)
- [x] 5.2 Edge case tests (conflicting roles, expired assignments, last-superadmin, unknown users)
- [x] 5.3 Audit store tests (hash chain, persistence across restarts, filtering)
- [x] 5.4 Config seeding tests
- [x] 5.5 Full test run: 144 tests, 20 test files, all passing
- [x] 5.6 TypeScript compilation: clean (exit 0)

## Verification Results (v0.7.0)
- **All 112 existing tests pass** — backward compatibility confirmed
- **32 new tests pass** — dual-auth, edge cases, audit, seeding
- **TypeScript compiles clean** — no errors
- ConfigRoleStore provides seamless backward compat when rbacStore disabled

## Phase 6: Runtime Policy Store & Zero-Config Bootstrap (v0.7.1)
- [x] 6.1 Create `src/core/policy-fields.ts` — 22 mutable field registry with parsing/validation
- [x] 6.2 Create `src/core/bootstrap.ts` — atomic first-owner bootstrap flow
- [x] 6.3 Add `resolveRole()` to RoleStore interface — dynamic RBAC role resolution
- [x] 6.4 Add policy override methods to RoleStore — get/set/delete/getAll
- [x] 6.5 Add `hasAnySuperadmin()` and `bootstrapOwner()` to RoleStore
- [x] 6.6 Implement in SqliteRoleStore — policy_overrides table, resolveRole query
- [x] 6.7 Implement ConfigRoleStore fallbacks — throws on writes, returns empty on reads
- [x] 6.8 Wire into openclaw-extension.ts — snapshot defaults, apply overrides, /sf setup, /sf policy
- [x] 6.9 Add policy commands to admin routes and CLI
- [x] 6.10 Refactor: extract atomic bootstrap, fix hot-path perf, fix dead retry bug
- [x] 6.11 Create test/bootstrap.test.ts — atomic bootstrap, rejection after first owner
- [x] 6.12 Create test/policy-store.test.ts — parsing, validation, snapshot, persistence
- [x] 6.13 All 176 tests pass (144 existing + 32 new)

## Verification Results (v0.7.1)
- **All 144 existing tests pass** — backward compatibility confirmed
- **32 new tests pass** — bootstrap, policy store, resolveRole
- **TypeScript compiles clean** — no errors
- Zero-config bootstrap works via chat (`/sf setup`) and CLI (`safefence setup`)
