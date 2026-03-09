# OpenClaw Guardrails

[![npm version](https://img.shields.io/npm/v/@safefence/openclaw-guardrails)](https://www.npmjs.com/package/@safefence/openclaw-guardrails)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)

> **Experimental** -- This project is under active development and not yet production-ready. APIs, config schemas, and behavior may change without notice between releases.

Native TypeScript security kernel for OpenClaw (`>=2026.2.25`) with deterministic local enforcement, principal-aware authorization, dual-authorization RBAC, and owner approval for group/multi-user safety.

## Install

```bash
openclaw plugins install @safefence/openclaw-guardrails
openclaw plugins list
```

### Configure `openclaw.config.ts`

```ts
import { defineConfig } from "openclaw/config";

export default defineConfig({
  plugins: {
    entries: {
      "openclaw-guardrails": {
        enabled: true,
        config: {
          workspaceRoot: "/workspace/project",
          mode: "enforce",
          failClosed: true
        }
      }
    }
  }
});
```

After changing plugin install/config, restart the OpenClaw service or gateway process so hook registration is reloaded.

## Usage

```ts
// 1. OpenClaw plugin — default export, auto-discovered via package.json
//    "openclaw.extensions". Registers all typed hooks via api.on().
import { openclawGuardrailsPlugin } from "@safefence/openclaw-guardrails";

// 2. Plugin factory — returns a guardrails engine with hook handlers,
//    useful for testing or manual integration.
import { createOpenClawGuardrailsPlugin } from "@safefence/openclaw-guardrails";

const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  mode: "enforce",
  failClosed: true
});

// Out-of-band owner approval
const token = plugin.approveRequest(requestId, "owner-user-id", "owner");

// 3. Engine directly — for custom integrations outside OpenClaw
import { GuardrailsEngine } from "@safefence/openclaw-guardrails";
const engine = new GuardrailsEngine(config);
const decision = await engine.evaluate(event);
```

### Custom Validators

```ts
import { GuardrailsEngine } from "@safefence/openclaw-guardrails";
import type { CustomValidator } from "@safefence/openclaw-guardrails";

const spendingLimit: CustomValidator = {
  id: "spending-limit",
  phases: ["before_tool_call"],
  validate({ event }) {
    if (event.toolName === "purchase" && event.args.amount > 1000) {
      return [{ ruleId: "spending-limit", reasonCode: "OVER_LIMIT", decision: "DENY", weight: 1 }];
    }
    return [];
  }
};

const engine = new GuardrailsEngine(config, { customValidators: [spendingLimit] });
```

### RBAC Store (Dual Authorization)

```ts
// Enable the persistent RBAC store in config
const config = {
  // ... existing config ...
  rbacStore: {
    enabled: true,
    dbPath: ".safefence/rbac.db",
    auditDbPath: ".safefence/audit.db",
    seedFromConfig: true,    // auto-import ownerIds/adminIds
    botPlatformId: "bot-123" // this bot's platform ID
  }
};

// Or use the SqliteRoleStore directly
import { SqliteRoleStore } from "@safefence/openclaw-guardrails";

const store = new SqliteRoleStore(config);
store.registerBot("project-1", "owner-user", "telegram", "bot-123", "My Bot");
store.createRole("project-1", "moderator", [
  { permissionId: "tool_use:read", effect: "allow" },
  { permissionId: "tool_use:write", effect: "allow" },
]);
// Effective permissions = user RBAC ∩ bot capabilities
const perms = store.resolveEffective({
  senderPlatform: "telegram",
  senderId: "user-456",
  botPlatform: "telegram",
  botPlatformId: "bot-123"
});
```

### Control Plane (Centralized Management)

Connect multiple OpenClaw instances to a centralized control plane for org-wide policy, RBAC, and audit management:

```ts
export default defineConfig({
  plugins: {
    entries: {
      "openclaw-guardrails": {
        enabled: true,
        config: {
          workspaceRoot: "/workspace/project",
          mode: "enforce",
          controlPlane: {
            enabled: true,
            endpoint: "https://safefence.example.com",
            orgApiKey: "sf_...",
            tags: ["production", "us-east"],
            groupId: "prod-cluster",
          }
        }
      }
    }
  }
});
```

When enabled, the plugin registers with the control plane, syncs policies and RBAC state, and streams audit events upstream. Local SQLite remains the enforcement cache — if the control plane is unreachable, enforcement continues with cached state. See the [Config Reference](docs/CONFIG.md#control-plane) for all options.

### Zero-Config Setup

Fresh installations require no config file edits. The plugin self-initializes and creates the SQLite database automatically:

```
# In chat — claim ownership on first install
/sf setup

# Or via CLI for headless environments
safefence setup --sender telegram:12345
```

The bootstrap is atomic (SQLite transaction) and one-time. Once an owner exists, `/sf setup` is rejected.

### Runtime Policy Management

22 config fields can be changed at runtime without restarting the gateway:

```
/sf policy show              # List all mutable fields with current values
/sf policy set mode audit    # Switch to audit mode immediately
/sf policy set limits.maxRequestsPerMinute 60
/sf policy reset mode        # Revert to original config file value
```

Changes are persisted in SQLite and restored on startup. See [Config Reference](docs/CONFIG.md#runtime-mutable-fields) for the full list of mutable fields.

### Bot Commands

When the RBAC store is enabled, the plugin registers `/sf` commands:

- `/sf setup` — zero-config first-owner bootstrap
- `/sf role create|delete|list|permissions|grant-perm|revoke-perm` — manage roles
- `/sf assign|revoke|who` — manage role assignments
- `/sf bot register|cap|access|list` — manage bot instances
- `/sf channel link|unlink` — link IM channels to projects
- `/sf policy list|show|get|set|reset` — runtime policy management
- `/sf audit` — query the audit log

### HTTP Admin API

```ts
import { createAdminServer } from "@safefence/openclaw-guardrails";

const server = createAdminServer({
  store,       // SqliteRoleStore instance
  port: 18790, // default
  apiKey: "your-api-key"
});
// REST API at http://localhost:18790/api/v1/...
```

## Exports

**Types**: `ApproverRole`, `ChannelType`, `DataClass`, `Decision`, `PrincipalContext`, `PrincipalRole`, `RolloutStage`, `GuardDecision`, `GuardEvent`, `GuardrailsConfig`, `ControlPlaneConfig`, `Phase`, `TokenUsageSummary`, `AuditEvent`, `AuditSink`, `CustomValidator`, `CustomValidatorContext`, `NotificationSink`, `ApprovalNotification`, `TokenUsageRecord`, `EngineOptions`, `PluginOptions`, `AuditEntry`, `AuditEventType`, `BotInstance`, `DeniedBy`, `DualAuthContext`, `EffectivePermissions`, `PermissionCheck`, `RbacRole`, `RbacRoleAssignment`, `RbacStoreConfig`, `RoleStore`, `AdminServerOptions`.

**Sync protocol types**: `InstanceIdentity`, `RegisterRequest`, `RegisterResponse`, `HeartbeatRequest`, `HeartbeatResponse`, `SyncEvent`, `PolicySyncResponse`, `RbacSyncResponse`, `AuditBatchRequest`, `AuditBatchResponse`, `LocalMutation`, `MutationBatchRequest`, `MutationBatchResponse`, `SyncAckRequest`.

**Constants**: `REASON_CODES`, `UNKNOWN_SENDER`, `UNKNOWN_CONVERSATION`, `AUDIT_EVENT_TYPES`.

**Classes**: `GuardrailsEngine`, `JsonlAuditSink`, `NoopAuditSink`, `ConsoleNotificationSink`, `CallbackNotificationSink`, `NoopNotificationSink`, `TokenUsageStore`, `ConfigRoleStore`, `SqliteRoleStore`, `AuditStore`.

**Sync classes**: `ControlPlaneAgent`, `ControlPlaneHttpClient`, `SseClient`, `SyncRoleStore`, `StreamingAuditSink`, `PolicySyncLoop`, `RbacSyncLoop`.

**Config helpers**: `createDefaultConfig()`, `mergeConfig(base, overrides)`, `createAdminServer()`.

**Policy store**: `MUTABLE_POLICY_FIELDS`, `MUTABLE_POLICY_KEYS`, `parseFieldValue()`, `validateFieldValue()`, `snapshotMutableDefaults()`, `applyPolicyOverrides()`, `getMutableDefault()`.

**Bootstrap**: `bootstrapFirstOwner()`.

## Limitations

- Deterministic patterns are not a full semantic jailbreak solution.
- Persistent approval store prunes expired records on write; replayed tokens are still caught within the TTL window. Approval tokens survive restarts when `storagePath` is configured.
- Retrieval trust still depends on upstream metadata quality.
- External validator circuit breaker state is module-scoped (shared across engine instances in the same process).
- Token usage `records` array grows unboundedly in memory for long-running processes. Use JSONL persistence and restart periodically for high-volume deployments.
- RBAC store requires `better-sqlite3` as an optional peer dependency. Without it, the system falls back to config-based authorization.

## Further Reading

- [Architecture & Internals](docs/ARCHITECTURE.md) — plugin flow, detector pipeline, security features, source layout
- [Config Reference](docs/CONFIG.md) — full configuration options
- [Migration Guide](docs/MIGRATION.md) — upgrade notes between versions
- [Research & Threat Analysis](../../docs/openclaw-llm-security-research.md)
- [Root Project Overview](../../README.md)

## Development

```bash
# From the repo root (pnpm workspace)
pnpm install
pnpm --filter @safefence/openclaw-guardrails test
pnpm --filter @safefence/openclaw-guardrails test:coverage
pnpm --filter @safefence/openclaw-guardrails build
```
