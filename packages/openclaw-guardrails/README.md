# OpenClaw Guardrails v2

Native TypeScript guardrails plugin for OpenClaw (`>=2026.2.25`) with deterministic local enforcement and no remote runtime dependency.

## Security Model

- Single security kernel (`GuardrailsEngine`) evaluates all hook phases.
- Declarative policy config controls allow/deny/redaction behavior.
- Monotonic precedence is enforced: `DENY > REDACT > ALLOW`.
- Audit mode preserves would-block telemetry and can still apply redaction.

## Threat Model Coverage (OWASP LLM)

- LLM01 Prompt Injection: input intent detector + pre-tool deny.
- LLM02 Sensitive Disclosure: secret/PII redaction and output safety sanitization.
- LLM03 Supply Chain: trusted source + hash requirements for `skills.install`.
- LLM04 Data/Model Poisoning: retrieval trust gate for high-risk tool execution.
- LLM05 Improper Output Handling: sanitize untrusted output before persistence.
- LLM06 Excessive Agency: strict tool and command binary allowlists.
- LLM07 System Prompt Leakage: deny prompt-leak patterns.
- LLM08 Vector/Embedding Weaknesses: retrieval trust metadata and signature gates.
- LLM09 Misinformation: trust-level gating before privileged actions.
- LLM10 Unbounded Consumption: size and per-agent budget limits.

## Architecture

- `src/core/engine.ts`: detector orchestration and policy evaluation.
- `src/core/detectors/*`: detector modules by control area.
- `src/core/path-canonical.ts`: canonical realpath enforcement.
- `src/core/command-parse.ts`: binary parsing and shell operator detection.
- `src/core/network-guard.ts`: host parsing + private/link-local blocking.
- `src/core/supply-chain.ts`: skill source/hash policy checks.
- `src/core/budget-store.ts`: per-agent sliding-window budgets.
- `src/core/retrieval-trust.ts`: retrieval trust/signature gating.

## Install

```bash
npm install
npm run build
```

## Usage

```ts
import { createOpenClawGuardrailsPlugin } from "@safefence/openclaw-guardrails";

const plugin = createOpenClawGuardrailsPlugin({
  workspaceRoot: "/workspace/project",
  mode: "enforce",
  failClosed: true,
  allow: {
    tools: ["read", "write", "edit", "exec", "process", "apply_patch", "skills.install"],
    commands: [
      { binary: "ls" },
      { binary: "cat" },
      { binary: "rg" },
      { binary: "git", argPattern: "^(status|diff)(\\s+.*)?$" }
    ],
    writablePaths: ["/workspace/project"],
    networkHosts: ["localhost", "127.0.0.1", "::1"],
    allowPrivateEgress: false
  }
});
```

## Configuration Migration (v1 -> v2)

1. Replace `allow.commandPrefixes` with `allow.commands`.
2. Add `deny.shellOperatorPatterns`.
3. Add budget limits: `maxRequestsPerMinute`, `maxToolCallsPerMinute`.
4. Add `pathPolicy` (canonical realpath + symlink traversal policy).
5. Add `supplyChain` trusted sources and hash requirements.
6. Add `retrievalTrust` if retrieval-backed actions are used.
7. Keep `redaction.applyInAuditMode=true` unless you explicitly want audit pass-through.

## Secure Defaults

- `mode: enforce`
- `failClosed: true`
- `allowPrivateEgress: false`
- `pathPolicy.enforceCanonicalRealpath: true`
- `pathPolicy.denySymlinkTraversal: true`
- `supplyChain.requireSkillHash: true`

## Tuning Playbook

1. Start in `audit` mode in pre-production and inspect reason codes.
2. Tighten `allow.commands` to the minimum binary/arg set your workload needs.
3. Expand `networkHosts` only for explicit business endpoints.
4. Pin skill hashes for approved skill sources.
5. Set budget limits based on observed per-agent baseline traffic.

## Known Limitations

- Deterministic pattern defenses can still miss novel semantic jailbreak phrasing.
- DNS outcomes can vary by environment; use explicit host allowlists to avoid ambiguity.
- Retrieval trust controls rely on upstream metadata correctness.

## Development

```bash
npm test
npm run build
```
