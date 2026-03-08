# Config Reference

Full configuration options for `@safefence/openclaw-guardrails`.

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| *(root)* | `mode` | `"enforce" \| "audit"` | `"enforce"` | Whether violations block or just log |
| *(root)* | `failClosed` | `boolean` | `true` | On engine error: DENY (true) or ALLOW (false) |
| *(root)* | `workspaceRoot` | `string` | `process.cwd()` | Anchor for path resolution |
| `allow` | `tools` | `string[]` | 8 tools | Allowed tool names |
| `allow` | `commands` | `CommandEntry[]` | 6 binaries | Allowed binaries with optional argPattern |
| `allow` | `writablePaths` | `string[]` | `[workspaceRoot]` | Filesystem write boundary |
| `allow` | `networkHosts` | `string[]` | localhost only | Allowed egress hosts |
| `allow` | `allowPrivateEgress` | `boolean` | `false` | Allow RFC 1918 / loopback destinations |
| `deny` | `commandPatterns` | `string[]` | 8 patterns | Destructive command regexes |
| `deny` | `pathPatterns` | `string[]` | 8 patterns | Path traversal regexes |
| `deny` | `promptInjectionPatterns` | `string[]` | 6 patterns | Injection attempt regexes |
| `deny` | `exfiltrationPatterns` | `string[]` | 4 patterns | Data exfiltration regexes |
| `deny` | `shellOperatorPatterns` | `string[]` | 9 patterns | Shell chaining/redirect regexes |
| `redaction` | `secretPatterns` | `string[]` | 7 patterns | Secret detection regexes (AWS, GitHub, PEM, etc.) |
| `redaction` | `piiPatterns` | `string[]` | 4 patterns | PII detection regexes (email, SSN, CC, phone) |
| `redaction` | `replacement` | `string` | `"[REDACTED]"` | Replacement string for matches |
| `redaction` | `applyInAuditMode` | `boolean` | `true` | Redact even when mode=audit |
| `limits` | `maxInputChars` | `number` | `20000` | Max input content length |
| `limits` | `maxToolArgChars` | `number` | `10000` | Max serialized tool args length |
| `limits` | `maxOutputChars` | `number` | `50000` | Max tool output length |
| `limits` | `maxRequestsPerMinute` | `number` | `120` | Rate limit: requests per 60s window |
| `limits` | `maxToolCallsPerMinute` | `number` | `60` | Rate limit: tool calls per 60s window |
| `pathPolicy` | `enforceCanonicalRealpath` | `boolean` | `true` | Resolve symlinks and verify workspace boundary |
| `pathPolicy` | `denySymlinkTraversal` | `boolean` | `true` | Block symlinks that escape workspace |
| `supplyChain` | `trustedSkillSources` | `string[]` | — | Allowed skill installation domains |
| `supplyChain` | `requireSkillHash` | `boolean` | `true` | Require hash for remote skills |
| `supplyChain` | `allowedSkillHashes` | `string[]` | — | Pre-approved skill hashes |
| `principal` | `requireContext` | `boolean` | `true` | Require identity context |
| `principal` | `ownerIds` | `string[]` | `[]` | User IDs with owner privilege |
| `principal` | `adminIds` | `string[]` | `[]` | User IDs with admin privilege |
| `principal` | `failUnknownInGroup` | `boolean` | `true` | Deny unknown users in group channels |
| `authorization` | `defaultEffect` | `"deny" \| "allow"` | `"deny"` | Default when no explicit rule matches |
| `authorization` | `requireMentionInGroups` | `boolean` | `true` | Require @mention for group messages |
| `authorization` | `restrictedTools` | `string[]` | 6 tools | Tools requiring elevated role or approval |
| `authorization` | `restrictedDataClasses` | `string[]` | — | Data classes requiring elevated access |
| `authorization` | `toolAllowByRole` | `Record<Role, string[]>` | Role-tiered | Per-role tool access lists |
| `approval` | `enabled` | `boolean` | `true` | Enable owner approval workflow |
| `approval` | `ttlSeconds` | `number` | `300` | Approval challenge TTL |
| `approval` | `requireForTools` | `string[]` | 6 tools | Tools requiring approval |
| `approval` | `requireForDataClasses` | `string[]` | `["restricted", "secret"]` | Data classes requiring approval |
| `approval` | `ownerQuorum` | `number` | `1` | Number of approvers required |
| `approval` | `bindToConversation` | `boolean` | `true` | Bind token to originating conversation |
| `approval` | `storagePath` | `string?` | — | JSON file for persistent approvals |
| `tenancy` | `budgetKeyMode` | `string` | `"agent+principal+conversation"` | Budget partitioning strategy |
| `tenancy` | `redactCrossPrincipalOutput` | `boolean` | `true` | Redact vs deny for restricted data |
| `outboundGuard` | `enabled` | `boolean` | `true` | Enable outbound leak prevention |
| `outboundGuard` | `systemPromptLeakPatterns` | `string[]` | 8 patterns | Patterns indicating prompt leakage |
| `outboundGuard` | `injectedFileNames` | `string[]` | 9 names | Config filenames to block in output |
| `rollout` | `stage` | `RolloutStage` | `"stage_c_full_enforce"` | Current enforcement stage |
| `rollout` | `highRiskTools` | `string[]` | — | Tools enforced in stage B |
| `monitoring` | `falsePositiveThresholdPct` | `number` | `3` | False positive rate threshold |
| `monitoring` | `consecutiveDaysForTuning` | `number` | `2` | Days above threshold before signaling |
| `audit` | `enabled` | `boolean` | `false` | Enable JSONL audit trail |
| `audit` | `sinkPath` | `string?` | — | File path for JSONL audit events |
| `externalValidation` | `enabled` | `boolean` | `false` | Enable HTTP external validators |
| `externalValidation` | `endpoint` | `string` | — | POST endpoint for validation requests |
| `externalValidation` | `timeoutMs` | `number?` | `5000` | Per-request timeout |
| `externalValidation` | `validators` | `string[]` | `[]` | Validator names to invoke |
| `externalValidation` | `failOpen` | `boolean` | `false` | Allow on timeout/error |
| `budgetPersistence` | `enabled` | `boolean` | `false` | Enable token usage tracking |
| `budgetPersistence` | `storagePath` | `string?` | — | JSONL path for usage persistence |
| `notifications` | `enabled` | `boolean` | `false` | Enable approval notifications |
| `notifications` | `adminChannelId` | `string?` | — | Target channel for notifications |
| `rbacStore` | `enabled` | `boolean` | `false` | Enable persistent RBAC store with dual authorization |
| `rbacStore` | `dbPath` | `string?` | `".safefence/rbac.db"` | SQLite database path for RBAC data |
| `rbacStore` | `auditDbPath` | `string?` | `".safefence/audit.db"` | Separate SQLite path for audit log |
| `rbacStore` | `auditRotation` | `"monthly" \| "quarterly" \| "off"` | `"monthly"` | Audit log file rotation policy |
| `rbacStore` | `seedFromConfig` | `boolean` | `false` | Auto-import ownerIds/adminIds as superadmin roles on first run |
| `rbacStore` | `botPlatformId` | `string?` | — | This bot's platform ID for self-identification |
| `rbacStore` | `apiKey` | `string?` | — | Bearer token for HTTP admin API authentication |
| `rbacStore` | `apiPort` | `number?` | `18790` | Port for HTTP admin API server |
| `controlPlane` | `enabled` | `boolean` | `false` | Connect to centralized control plane |
| `controlPlane` | `endpoint` | `string` | — | Control plane URL (e.g. `https://safefence.example.com`) |
| `controlPlane` | `orgApiKey` | `string` | — | Organization API key (`sf_...`) |
| `controlPlane` | `tags` | `string[]?` | — | Instance tags for fleet organization |
| `controlPlane` | `groupId` | `string?` | — | Instance group for per-environment policy overrides |
| `controlPlane` | `syncIntervalMs` | `number?` | `30000` | Mutation flush interval |
| `controlPlane` | `heartbeatIntervalMs` | `number?` | `30000` | Heartbeat report interval |
| `controlPlane` | `auditFlushIntervalMs` | `number?` | `5000` | Audit batch upload interval |
| `controlPlane` | `auditBatchSize` | `number?` | `500` | Max events per audit batch |
| `controlPlane` | `instanceDataPath` | `string?` | `".safefence/instance.json"` | Path for persistent instance identity |

## Runtime-Mutable Fields

The following 22 config fields can be changed at runtime via `/sf policy set <key> <value>` without restarting the gateway. All other fields require a config file change and restart.

| Key | Type | Description |
|-----|------|-------------|
| `mode` | `"enforce" \| "audit"` | Operating mode |
| `rollout.stage` | `RolloutStage` | Current enforcement stage |
| `limits.maxInputChars` | `number` | Max input content length (must be > 0) |
| `limits.maxToolArgChars` | `number` | Max serialized tool args length (must be > 0) |
| `limits.maxOutputChars` | `number` | Max tool output length (must be > 0) |
| `limits.maxRequestsPerMinute` | `number` | Rate limit: requests per 60s window (must be > 0) |
| `limits.maxToolCallsPerMinute` | `number` | Rate limit: tool calls per 60s window (must be > 0) |
| `allow.tools` | `string[]` | Allowed tool names |
| `allow.networkHosts` | `string[]` | Allowed egress hosts |
| `allow.allowPrivateEgress` | `boolean` | Allow RFC 1918 / loopback destinations |
| `deny.commandPatterns` | `string[]` | Destructive command regexes |
| `authorization.restrictedTools` | `string[]` | Tools requiring elevated role or approval |
| `approval.enabled` | `boolean` | Enable owner approval workflow |
| `approval.ttlSeconds` | `number` | Approval challenge TTL (must be > 0) |
| `approval.requireForTools` | `string[]` | Tools requiring approval |
| `approval.ownerQuorum` | `number` | Number of approvers required (must be > 0) |
| `monitoring.falsePositiveThresholdPct` | `number` | False positive rate threshold (must be > 0) |
| `monitoring.consecutiveDaysForTuning` | `number` | Days above threshold before signaling (must be > 0) |
| `notifications.enabled` | `boolean` | Enable approval notifications |
| `notifications.adminChannelId` | `string` | Target channel for notifications |
| `supplyChain.requireSkillHash` | `boolean` | Require hash for remote skills |
| `supplyChain.allowedSkillHashes` | `string[]` | Pre-approved skill hashes |

Policy overrides are persisted in the `policy_overrides` SQLite table and restored on startup. Changes via `/sf policy set` take effect immediately and survive gateway restarts. Use `/sf policy reset <key>` to revert to the original config file value.

## Control Plane

The `controlPlane` section configures optional connectivity to the SafeFence centralized control plane. When `enabled: false` (default), the plugin operates in standalone mode — identical to previous versions.

### Minimal Configuration

```ts
{
  controlPlane: {
    enabled: true,
    endpoint: "https://safefence.example.com",
    orgApiKey: "sf_..."
  }
}
```

### What It Does

When enabled, the plugin:

1. **Registers** with the control plane on startup (receives a JWT instance token).
2. **Pulls** a full policy and RBAC snapshot, applying to local SQLite.
3. **Opens an SSE stream** for real-time change notifications.
4. **Sends heartbeats** every 30s with sync versions and evaluation metrics.
5. **Streams audit events** in batches every 5s via REST.
6. **Flushes local mutations** (role changes made via `/sf` commands) upstream.

### Offline Behavior

If the control plane is unreachable, the plugin continues enforcing with cached local state. Audit events buffer in memory (up to 10,000) and replay from cursor on reconnect. Local `/sf` commands continue working; mutations queue for upstream sync.

### Instance Identity

Each plugin instance generates a persistent UUID stored at `instanceDataPath` (default: `.safefence/instance.json`). This identity survives restarts and is used for registration, heartbeat, and audit tracking.
