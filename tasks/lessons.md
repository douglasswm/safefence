# Lessons Learned

## 2026-03-09: Always follow CLAUDE.md workflow

- **Mistake**: Jumped straight into implementation of a 9-task plan without entering plan mode, writing todo.md, or exploring the build system first.
- **Root cause**: Treated a complex multi-file security hardening as a simple task.
- **Rule**: ANY task with 3+ steps → write `tasks/todo.md` first, verify plan, then implement. No exceptions.
- **Rule**: Before running build/test commands, verify the project structure (e.g., no root package.json in this monorepo — must build per-package with `pnpm --filter <pkg> build`).

## 2026-03-09: ioredis import under NodeNext moduleResolution

- **Mistake**: Assumed pre-existing TS errors were not fixable / out of scope.
- **Root cause**: ioredis uses `export { default }` which under `moduleResolution: NodeNext` becomes a namespace, not a class. Use `import { Redis } from "ioredis"` (named export) instead of `import Redis from "ioredis"` (default export).
- **Rule**: When adding new code that follows an existing broken pattern (e.g., `import type Redis from "ioredis"` matching `sse-broadcaster.ts`), fix the pattern everywhere rather than copying the bug.
