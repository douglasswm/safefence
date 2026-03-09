# @safefence/types

Shared protocol-boundary types for the SafeFence monorepo. This package is the single source of truth for the three enumeration types exchanged between the control plane, dashboard, guardrails agent, and any external tooling.

## What it exports

### Type aliases (compile-time only)

| Type | Values |
|------|--------|
| `InstanceStatus` | `"registered" \| "active" \| "connected" \| "disconnected" \| "deregistered" \| "stale"` |
| `PolicyScope` | `"org" \| "group" \| "instance"` |
| `AuditDecision` | `"allow" \| "deny"` |

### Const objects (runtime values)

| Const | Keys |
|-------|------|
| `INSTANCE_STATUS` | `REGISTERED`, `ACTIVE`, `CONNECTED`, `DISCONNECTED`, `DEREGISTERED`, `STALE` |
| `POLICY_SCOPE` | `ORG`, `GROUP`, `INSTANCE` |
| `AUDIT_DECISION` | `ALLOW`, `DENY` |

Each const object member uses `as const`, so TypeScript narrows values to their literal types rather than `string`.

## Usage

```typescript
import { INSTANCE_STATUS, type InstanceStatus } from "@safefence/types";

// Runtime comparison
if (instance.status === INSTANCE_STATUS.CONNECTED) { ... }

// Type annotation
function setStatus(s: InstanceStatus) { ... }
```

## How it's consumed

All three packages in the monorepo depend on `@safefence/types` as a workspace package:

| Package | Imports |
|---------|---------|
| `@safefence/control-plane` | All three types + consts (used in Drizzle column defaults) |
| `@safefence/dashboard` | All three types + consts (used to type the `Instance` interface) |
| `@safefence/openclaw-guardrails` | `PolicyScope` only (used in sync protocol types) |

Each consumer re-exports what it needs from a local barrel file, so internal code imports from the local barrel rather than reaching into this package directly.

## Stability

This package follows semver. The exported types are protocol-boundary contracts — changes that add new values to a union are minor bumps; changes that remove or rename values are major bumps.

## Build

```bash
pnpm --filter @safefence/types build
```

Output goes to `dist/`. ESM only (`"type": "module"`), targeting ES2022.
