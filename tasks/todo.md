# OpenClaw Guardrails Plugin Distribution + README Update

## Plan

- [x] Confirm OpenClaw plugin distribution and manifest requirements from official docs.
- [x] Add OpenClaw npm package metadata (`openclaw.extensions`) in package manifest.
- [x] Add required plugin manifest identity (`id`) in `openclaw.plugin.json`.
- [x] Add plugin runtime extension entrypoint with default export registration contract.
- [x] Keep direct library API compatibility (`createOpenClawGuardrailsPlugin`).
- [x] Update package README with npm install/config/verify/remove/test steps for OpenClaw.
- [x] Add regression tests for distribution metadata and runtime hook registration contract.
- [x] Run verification: `npm test`, `npm run build`, `npm pack --dry-run --cache ./.npm-cache`.
- [x] Add review results with evidence.

## Review

- `npm test` passed: 13 files, 41 tests.
- `npm run build` passed (`tsc -p tsconfig.json`).
- `npm pack --dry-run --cache ./.npm-cache` passed and includes:
  - `dist/plugin/openclaw-extension.js`
  - `openclaw.plugin.json`
  - updated package `README.md`
- Local OpenClaw runtime validation remains manual in this workspace because `openclaw` CLI is not installed (`command not found`).

---

# Root README Publish Runbook Update

## Plan

- [x] Research official OpenClaw npm plugin distribution and CLI behavior.
- [x] Research official npm publish command guidance.
- [x] Update root `README.md` with OpenClaw plugin publish runbook.
- [x] Add source links in root documentation section.

## Review

- Added publish instructions to `/README.md` covering pre-publish checks, release/prerelease publish commands, and OpenClaw validation steps.
- Included direct links to OpenClaw plugin docs, OpenClaw plugin CLI docs, and npm publish docs.
