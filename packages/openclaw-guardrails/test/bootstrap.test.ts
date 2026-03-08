import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { ConfigRoleStore } from "../src/core/config-role-store.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";
import type { GuardrailsConfig } from "../src/core/types.js";

let SqliteRoleStore: typeof import("../src/core/sqlite-role-store.js").SqliteRoleStore | undefined;

try {
  require("better-sqlite3");
  SqliteRoleStore = (await import("../src/core/sqlite-role-store.js")).SqliteRoleStore;
} catch {
  // better-sqlite3 not available — SQLite tests will be skipped
}

// Dynamic import of bootstrap (depends on SqliteRoleStore availability)
const { bootstrapFirstOwner } = await import("../src/core/bootstrap.js");

describe("ConfigRoleStore bootstrap", () => {
  it("throws on bootstrapOwner", () => {
    const config = createDefaultConfig("/tmp/test");
    const store = new ConfigRoleStore(config);
    expect(() => store.bootstrapOwner("telegram:123")).toThrow("Enable rbacStore");
  });

  it("hasAnySuperadmin returns true when ownerIds non-empty", () => {
    const config = createDefaultConfig("/tmp/test");
    config.principal.ownerIds = ["telegram:123"];
    const store = new ConfigRoleStore(config);
    expect(store.hasAnySuperadmin()).toBe(true);
  });

  it("hasAnySuperadmin returns false when ownerIds empty", () => {
    const config = createDefaultConfig("/tmp/test");
    const store = new ConfigRoleStore(config);
    expect(store.hasAnySuperadmin()).toBe(false);
  });
});

describe.skipIf(!SqliteRoleStore)("SqliteRoleStore bootstrap", () => {
  let tmpDir: string;
  let store: InstanceType<typeof import("../src/core/sqlite-role-store.js").SqliteRoleStore>;

  beforeEach(() => {
    tmpDir = join(tmpdir(), `safefence-test-${randomUUID()}`);
    mkdirSync(tmpDir, { recursive: true });
    store = new SqliteRoleStore!(
      join(tmpDir, "rbac.db"),
      join(tmpDir, "audit.db")
    );
  });

  afterEach(() => {
    store.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("hasAnySuperadmin returns false on fresh store", () => {
    expect(store.hasAnySuperadmin()).toBe(false);
  });

  it("bootstrapOwner succeeds on fresh store", () => {
    const result = bootstrapFirstOwner(store, "telegram:12345", "test");

    expect(result.success).toBe(true);
    expect(result.ownerId).toBe("telegram:12345");
    expect(result.projectId).toBe("default-project");
  });

  it("hasAnySuperadmin returns true after bootstrap", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");
    expect(store.hasAnySuperadmin()).toBe(true);
  });

  it("rejects second bootstrap attempt", () => {
    const first = bootstrapFirstOwner(store, "telegram:12345", "test");
    expect(first.success).toBe(true);

    const second = bootstrapFirstOwner(store, "telegram:67890", "test");
    expect(second.success).toBe(false);
    expect(second.error).toContain("already");
  });

  it("creates default org and project", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    const roles = store.listRoles("default-project");
    expect(roles.length).toBeGreaterThan(0);
    expect(roles.some((r) => r.name === "superadmin")).toBe(true);
  });

  it("links platform identity from compound ID", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    const userId = store.resolveUserId("telegram", "12345");
    expect(userId).toBe("telegram:12345");
  });

  it("audit-logs the bootstrap event", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    const entries = store.queryAudit({ eventType: "setup.bootstrap" });
    expect(entries.length).toBe(1);
    expect(entries[0].actorUserId).toBe("telegram:12345");
  });

  it("resolveRole returns owner for bootstrapped user", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    const role = store.resolveRole("telegram", "12345");
    expect(role).toBe("owner");
  });
});
