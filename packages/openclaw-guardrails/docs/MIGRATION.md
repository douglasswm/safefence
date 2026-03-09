# Migration Guide

## v0.8.0 → current (security hardening)

1. **TLS enforcement (agent side)**: `ControlPlaneHttpClient` now rejects non-HTTPS control plane endpoints for non-localhost hosts when `NODE_ENV=production`. The check is a startup-time guard — if your endpoint uses `http://` and is not localhost, the agent will throw on startup.

   - **No action needed** for most deployments: localhost development (`http://localhost:3100`) is always permitted.
   - **Action needed** if you use a plain HTTP endpoint in production: either switch the endpoint to `https://` (recommended), or set `requireTls: false` in your `controlPlane` config block as an explicit override.

2. **No other breaking changes**: All control plane REST endpoints, sync protocol, audit format, RBAC store, and plugin APIs are unchanged.

---

## v0.7.1 → v0.8.0

1. **Control plane sync (opt-in)**: New `controlPlane` config section enables centralized policy, RBAC, and audit management. Default is `controlPlane.enabled: false` — no behavioral change for existing deployments. When enabled, the plugin registers with a control plane server and syncs state via REST + SSE.

2. **New `ControlPlaneConfig` type**: Added to `GuardrailsConfig`. Fields: `enabled`, `endpoint`, `orgApiKey`, `tags`, `groupId`, `syncIntervalMs`, `heartbeatIntervalMs`, `auditFlushIntervalMs`, `auditBatchSize`, `instanceDataPath`.

3. **New `src/sync/` directory**: 8 new files for agent-side sync components:
   - `types.ts` — shared protocol types (registration, heartbeat, sync events, audit batches, mutations)
   - `http-client.ts` — REST client for control plane API
   - `sse-client.ts` — SSE client with auto-reconnect and exponential backoff
   - `sync-role-store.ts` — `RoleStore` wrapper that queues mutations for upstream sync
   - `streaming-audit-sink.ts` — `AuditSink` wrapper that buffers and flushes events upstream
   - `policy-sync-loop.ts` — SSE-triggered policy delta pull and local application
   - `rbac-sync-loop.ts` — SSE-triggered RBAC snapshot pull and local application
   - `control-plane-agent.ts` — orchestrator for registration, heartbeat, and lifecycle

4. **New exports**: `ControlPlaneAgent`, `ControlPlaneHttpClient`, `SseClient`, `SyncRoleStore`, `StreamingAuditSink`, `PolicySyncLoop`, `RbacSyncLoop`, plus all protocol types from `src/sync/types.ts`.

5. **New utility**: `toError()` in `src/utils/args.ts` for consistent error coercion.

6. **Integration change in `openclaw-extension.ts`**: When `controlPlane.enabled`, the plugin wraps `RoleStore` with `SyncRoleStore` and passes `StreamingAuditSink` to the guardrails engine. The engine and detectors are unchanged.

7. **New companion packages** (separate from this package):
   - `@safefence/control-plane` — Hono REST API + PostgreSQL + Redis SSE broadcaster
   - `@safefence/dashboard` — Next.js admin dashboard

8. **No breaking changes**: All existing APIs, config options, and behavior are preserved. The control plane integration is entirely additive.

9. **Test count**: 186 tests across 22 test files (up from 176). No regressions.

## v0.7.0 → v0.7.1

1. **Runtime policy store**: 22 guardrail config fields can now be changed at runtime via `/sf policy set <key> <value>`. Changes are persisted in SQLite and restored on startup. No breaking changes — all fields remain configurable via the config file.

2. **Zero-config bootstrap**: Fresh installations no longer require `ownerIds` in the config file. Run `/sf setup` in chat (or `safefence setup` via CLI) to claim ownership. The bootstrap is atomic (SQLite transaction) and one-time — rejected after the first superadmin exists.

3. **Dynamic RBAC role resolution**: New `resolveRole(platform, platformId)` method on `RoleStore`. The plugin now queries the RBAC store for role resolution before falling back to static `ownerIds`/`adminIds`. This means bootstrapped owners work without config file edits.

4. **New files**: `src/core/bootstrap.ts` (atomic bootstrap flow), `src/core/policy-fields.ts` (mutable field registry, parsing, validation).

5. **New `/sf` commands**: `policy list`, `policy show`, `policy get <key>`, `policy set <key> <value>`, `policy reset <key>`, `setup`.

6. **New RoleStore methods**: `resolveRole()`, `getPolicyOverride()`, `getAllPolicyOverrides()`, `setPolicyOverride()`, `deletePolicyOverride()`, `hasAnySuperadmin()`, `bootstrapOwner()`.

7. **Performance**: Hot-path identity resolution optimized, dead retry bug fixed in policy/setup code.

8. **Test count**: 176 tests across 22 test files (up from 144 across 20). New: `bootstrap.test.ts`, `policy-store.test.ts`.

## v0.6.5 → v0.7.0

1. **Dual-authorization RBAC store**: New persistent SQLite-backed RBAC system. Enable via `rbacStore.enabled: true` in config. When disabled (default), behavior is identical to previous versions — no breaking changes.

2. **New `DualAuthContext` interface**: `RoleStore.resolveEffective()` and `checkPermission()` now accept a single `DualAuthContext` object instead of 5 positional parameters. This only affects users who import and call `RoleStore` directly.

3. **New types exported**: `DualAuthContext`, `DeniedBy`, `AuditEventType`, `AuditEntry`, `BotInstance`, `EffectivePermissions`, `PermissionCheck`, `RbacRole`, `RbacRoleAssignment`, `RbacStoreConfig`, `RoleStore`. New constant: `AUDIT_EVENT_TYPES`.

4. **New classes exported**: `SqliteRoleStore`, `ConfigRoleStore`, `AuditStore`.

5. **New peer dependency**: `better-sqlite3` (optional). Only required when `rbacStore.enabled: true`. Install with `pnpm add better-sqlite3`.

6. **Bot commands**: When RBAC store is enabled, the plugin registers `/sf` commands for role management, bot configuration, and audit queries. These commands require appropriate permissions (e.g., `admin:role_manage`).

7. **HTTP admin API**: Optional REST API server created via `createAdminServer()`. Requires `rbacStore.apiKey` for authentication.

8. **CLI tool**: New `safefence` binary for direct SQLite management. Added to `package.json` `bin` field.

9. **Audit logging**: RBAC decisions and admin mutations are logged to a separate hash-chained SQLite audit log (`audit.db`). Existing JSONL audit sink continues unchanged for guardrail content-safety events.

10. **Test count**: 144 tests across 20 test files (up from 112 across 19).

## v0.6.0 → v0.6.1

1. **Plugin API alignment**: The plugin now uses OpenClaw's typed hook system (`api.on()`) instead of `api.registerHook()`. Security decisions (block, cancel, redact) are now properly honoured by OpenClaw's pipeline — previously they were silently discarded.
2. **New event adapter layer**: `src/plugin/event-adapter.ts` bridges OpenClaw's structured `(event, ctx)` hook pairs to the internal `OpenClawContext`. No changes needed for users of `createOpenClawGuardrailsPlugin()` or `GuardrailsEngine` directly.
3. **Plugin export**: The default export is now an `{ id, name, version, register }` object (compatible with `resolvePluginModuleExport()`). The `registerOpenClawGuardrails` named export is preserved for backward compatibility.
4. **`tool_result_persist` sync redaction**: Uses the existing `redactWithPatterns()` utility for synchronous redaction. Full async engine evaluation runs fire-and-forget for audit/metrics.
5. **Manifest cleaned**: Removed unrecognized `entry` and `hooks` fields from `openclaw.plugin.json`. Set `additionalProperties: false` on root config schema.
6. **Peer dependency**: `openclaw` is now declared as a `peerDependency` (`>=2026.2.25`).

## v0.5.x → v0.6.0

1. `GuardrailsEngine` constructor now takes `(config, options?)` instead of `(config, budgetStore?, approvalBroker?)`. Pass dependencies via `EngineOptions`.
2. `createOpenClawGuardrailsPlugin()` accepts both `Partial<GuardrailsConfig>` (unchanged) and `PluginOptions` (new) for injecting audit sinks, notification sinks, etc.
3. New config sections (`audit`, `externalValidation`, `budgetPersistence`, `notifications`) default to disabled — no breaking changes for existing configs.
4. New reason codes: `EXTERNAL_VALIDATION_FAILED`, `EXTERNAL_VALIDATION_TIMEOUT`.

## v0.3.x → v0.4.0

1. Add `principal`, `authorization`, `approval`, and `tenancy` config blocks.
2. Pass sender/channel metadata in hook contexts (`senderId`, `conversationId`, `channelType`, `mentionedAgent`).
3. Integrate owner approval handling via `approvalChallenge.requestId` + `plugin.approveRequest(...)`.
4. Keep secure defaults unless you have a validated exception.
5. Use `rollout.stage` for staged deployment and monitor `metadata.guardrailsMonitoring`.
6. **Breaking**: callers can no longer self-assign privileged roles (`owner`/`admin`) via `metadata.role`. Privileged roles are now derived exclusively from `principal.ownerIds`/`adminIds` in config. Any caller-supplied `"owner"` or `"admin"` role is downgraded to `"member"`.
