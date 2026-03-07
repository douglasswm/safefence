# Migration Guide

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
