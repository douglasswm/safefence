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

```bash
cd packages/openclaw-guardrails

# Pre-publish
npm whoami && npm test && npm run build
npm pack --dry-run --cache ./.npm-cache

# Publish (use --tag beta for prereleases)
npm publish --access public

# Verify
npm view @safefence/openclaw-guardrails version
openclaw plugins install @safefence/openclaw-guardrails@<version>
openclaw plugins list
```

Ensure `package.json` has `openclaw.extensions` pointing to `./dist/plugin/openclaw-extension.js`, and the tarball includes `dist/**`, `openclaw.plugin.json`, and `README.md`.

## Documentation

- Package docs: [`packages/openclaw-guardrails/README.md`](./packages/openclaw-guardrails/README.md)
- Research report: [`docs/openclaw-llm-security-research.md`](./docs/openclaw-llm-security-research.md)

## Compatibility

- OpenClaw target: `>=2026.2.25`
- Node.js: `>=20`
- TypeScript: `5.x`
