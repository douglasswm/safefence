# SafeFence

Security-focused tooling for hardening OpenClaw agent deployments, with emphasis on OWASP LLM Top 10 controls, deterministic guardrails, and multi-user safety.

## Repository Layout

- `packages/openclaw-guardrails`: production TypeScript guardrails library/plugin.
- `docs/openclaw-llm-security-research.md`: threat research, OWASP mapping, and hardening guidance.
- `CLAUDE.md`: local engineering workflow and coding standards.

## What This Project Delivers

The current implementation centers on `openclaw-guardrails` v3, including:

- deterministic security kernel with fixed evaluation order;
- prompt injection, command, path, network, provenance, and output-safety detectors;
- principal-aware authorization for group and multi-user contexts;
- owner-approval workflow with TTL, anti-replay, conversation binding, and optional persistence;
- staged rollout controls (`stage_a_audit`, `stage_b_high_risk_enforce`, `stage_c_full_enforce`);
- runtime monitoring snapshot with false-positive threshold signaling;
- regression and security-focused test coverage.

## Quick Start (Current Package)

```bash
cd packages/openclaw-guardrails
npm install
npm test
npm run test:coverage
npm run build
```

## Publish the OpenClaw Plugin (npm)

Use this runbook to publish `@safefence/openclaw-guardrails` so it can be installed with `openclaw plugins install <npm-spec>`.

### 1) Pre-publish checklist

```bash
cd packages/openclaw-guardrails
npm whoami
npm test
npm run build
npm pack --dry-run --cache ./.npm-cache
```

Validate packaging contract before publishing:

- `package.json` includes `openclaw.extensions` pointing to the built plugin entry (`./dist/plugin/openclaw-extension.js`).
- `openclaw.plugin.json` includes `id` and `configSchema`.
- Tarball output includes `dist/**`, `openclaw.plugin.json`, and `README.md`.

### 2) Publish to npm

```bash
cd packages/openclaw-guardrails
npm publish --access public
```

For prereleases:

```bash
npm publish --tag beta --access public
```

### 3) Validate published install path in OpenClaw

```bash
npm view @safefence/openclaw-guardrails version
openclaw plugins install @safefence/openclaw-guardrails@<version>
openclaw plugins list
openclaw plugins info openclaw-guardrails
```

Then restart Gateway/OpenClaw and confirm the plugin is configured under `plugins.entries.openclaw-guardrails`.

Optional cleanup:

```bash
openclaw plugins uninstall openclaw-guardrails
```

### 4) Notes

- OpenClaw npm plugin installs are registry specs only (package name + optional version/tag), not Git/URL specs.
- OpenClaw installs plugin dependencies with `npm install --ignore-scripts`, so keep dependencies compatible with no lifecycle scripts.
- If publishing from supported CI, use npm provenance (`npm publish --provenance`) for stronger supply-chain attestations.

## Documentation

- Package docs: [`packages/openclaw-guardrails/README.md`](./packages/openclaw-guardrails/README.md)
- Research report: [`docs/openclaw-llm-security-research.md`](./docs/openclaw-llm-security-research.md)
- OpenClaw plugins docs: [`docs.openclaw.ai/tools/plugin`](https://docs.openclaw.ai/tools/plugin)
- OpenClaw plugin CLI docs: [`docs.openclaw.ai/cli/plugins`](https://docs.openclaw.ai/cli/plugins)
- npm publish docs: [`docs.npmjs.com/cli/v11/commands/npm-publish`](https://docs.npmjs.com/cli/v11/commands/npm-publish)

## Compatibility

- OpenClaw target: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`
