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
