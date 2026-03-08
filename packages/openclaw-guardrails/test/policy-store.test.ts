import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import {
  applyPolicyOverrides,
  getConfigValue,
  getMutableDefault,
  MUTABLE_POLICY_FIELD_MAP,
  parseFieldValue,
  setConfigValue,
  snapshotMutableDefaults,
  validateFieldValue,
} from "../src/core/policy-fields.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";
import type { GuardrailsConfig } from "../src/core/types.js";

let SqliteRoleStore: typeof import("../src/core/sqlite-role-store.js").SqliteRoleStore | undefined;

try {
  require("better-sqlite3");
  SqliteRoleStore = (await import("../src/core/sqlite-role-store.js")).SqliteRoleStore;
} catch {
  // better-sqlite3 not available — SQLite tests will be skipped
}

// ═══════════════════════════════════════════
// parseFieldValue / validateFieldValue
// ═══════════════════════════════════════════

describe("parseFieldValue", () => {
  it("parses number", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("limits.maxRequestsPerMinute")!;
    expect(parseFieldValue(field, "200")).toBe(200);
  });

  it("rejects invalid number", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("limits.maxRequestsPerMinute")!;
    expect(() => parseFieldValue(field, "abc")).toThrow("Invalid number");
  });

  it("parses boolean true/false", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("approval.enabled")!;
    expect(parseFieldValue(field, "true")).toBe(true);
    expect(parseFieldValue(field, "false")).toBe(false);
  });

  it("rejects invalid boolean", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("approval.enabled")!;
    expect(() => parseFieldValue(field, "yes")).toThrow("Invalid boolean");
  });

  it("parses comma-separated string array", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("allow.tools")!;
    expect(parseFieldValue(field, "read, write, exec")).toEqual(["read", "write", "exec"]);
  });

  it("parses JSON string array", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("allow.tools")!;
    expect(parseFieldValue(field, '["read","write"]')).toEqual(["read", "write"]);
  });

  it("parses JSON object", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("authorization.toolAllowByRole")!;
    const result = parseFieldValue(field, '{"owner":["read","write"]}');
    expect(result).toEqual({ owner: ["read", "write"] });
  });

  it("parses string", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("mode")!;
    expect(parseFieldValue(field, "audit")).toBe("audit");
  });
});

describe("validateFieldValue", () => {
  it("accepts valid mode", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("mode")!;
    expect(validateFieldValue(field, "enforce")).toBeNull();
    expect(validateFieldValue(field, "audit")).toBeNull();
  });

  it("rejects invalid mode", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("mode")!;
    expect(validateFieldValue(field, "invalid")).not.toBeNull();
  });

  it("rejects wrong type", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("limits.maxRequestsPerMinute")!;
    expect(validateFieldValue(field, "not-a-number")).not.toBeNull();
  });

  it("rejects non-positive number for positive-only fields", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("limits.maxRequestsPerMinute")!;
    expect(validateFieldValue(field, 0)).not.toBeNull();
    expect(validateFieldValue(field, -1)).not.toBeNull();
  });

  it("accepts valid positive number", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("limits.maxRequestsPerMinute")!;
    expect(validateFieldValue(field, 100)).toBeNull();
  });

  it("rejects non-array for string[] field", () => {
    const field = MUTABLE_POLICY_FIELD_MAP.get("allow.tools")!;
    expect(validateFieldValue(field, "not-an-array")).not.toBeNull();
  });
});

// ═══════════════════════════════════════════
// snapshotMutableDefaults / getMutableDefault
// ═══════════════════════════════════════════

describe("snapshotMutableDefaults + getMutableDefault", () => {
  it("captures and retrieves defaults", () => {
    const config = createDefaultConfig("/tmp/test");
    snapshotMutableDefaults(config);

    expect(getMutableDefault("mode")).toBe("enforce");
    expect(getMutableDefault("limits.maxRequestsPerMinute")).toBe(120);
  });

  it("deep-copies arrays so mutations don't affect snapshot", () => {
    const config = createDefaultConfig("/tmp/test");
    snapshotMutableDefaults(config);

    // Mutate the config
    (config.allow as { tools: string[] }).tools = ["changed"];

    // Snapshot should be unaffected
    const defaultTools = getMutableDefault("allow.tools") as string[];
    expect(defaultTools).toContain("read");
    expect(defaultTools).not.toContain("changed");
  });
});

// ═══════════════════════════════════════════
// getConfigValue / setConfigValue
// ═══════════════════════════════════════════

describe("getConfigValue / setConfigValue", () => {
  it("gets nested value", () => {
    const config = createDefaultConfig("/tmp/test");
    expect(getConfigValue(config, "limits.maxRequestsPerMinute")).toBe(120);
  });

  it("sets nested value", () => {
    const config = createDefaultConfig("/tmp/test");
    setConfigValue(config, "limits.maxRequestsPerMinute", 999);
    expect(getConfigValue(config, "limits.maxRequestsPerMinute")).toBe(999);
  });

  it("returns undefined for missing path", () => {
    const config = createDefaultConfig("/tmp/test");
    expect(getConfigValue(config, "nonexistent.path")).toBeUndefined();
  });
});

// ═══════════════════════════════════════════
// SqliteRoleStore policy overrides
// ═══════════════════════════════════════════

describe.skipIf(!SqliteRoleStore)("SqliteRoleStore policy overrides", () => {
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

  it("set + get round-trip", () => {
    store.setPolicyOverride("mode", "audit", "test-user");
    expect(store.getPolicyOverride("mode")).toBe("audit");
  });

  it("getAllPolicyOverrides returns all set overrides", () => {
    store.setPolicyOverride("mode", "audit");
    store.setPolicyOverride("limits.maxRequestsPerMinute", 200);

    const all = store.getAllPolicyOverrides();
    expect(all.length).toBe(2);
    expect(all.find((o) => o.key === "mode")?.value).toBe("audit");
    expect(all.find((o) => o.key === "limits.maxRequestsPerMinute")?.value).toBe(200);
  });

  it("deletePolicyOverride removes override", () => {
    store.setPolicyOverride("mode", "audit");
    expect(store.getPolicyOverride("mode")).toBe("audit");

    store.deletePolicyOverride("mode");
    expect(store.getPolicyOverride("mode")).toBeUndefined();
  });

  it("rejects non-mutable key", () => {
    expect(() => store.setPolicyOverride("workspaceRoot", "/tmp")).toThrow("not a mutable field");
  });

  it("audit-logs POLICY_SET with previous value", () => {
    store.setPolicyOverride("mode", "audit", "user-1");
    store.setPolicyOverride("mode", "enforce", "user-2");

    const entries = store.queryAudit({ eventType: "policy.set" });
    expect(entries.length).toBe(2);
  });

  it("audit-logs POLICY_DELETE", () => {
    store.setPolicyOverride("mode", "audit");
    store.deletePolicyOverride("mode");

    const entries = store.queryAudit({ eventType: "policy.delete" });
    expect(entries.length).toBe(1);
  });

  it("applyPolicyOverrides mutates config from stored overrides", () => {
    const config = createDefaultConfig("/tmp/test");
    expect(config.mode).toBe("enforce");

    store.setPolicyOverride("mode", "audit");
    applyPolicyOverrides(config, store);

    expect(config.mode).toBe("audit");
  });

  it("overrides persist across store reinit", () => {
    const dbPath = join(tmpDir, "rbac.db");
    const auditDbPath = join(tmpDir, "audit.db");

    store.setPolicyOverride("mode", "audit");
    store.close();

    // Re-init store from same db
    const store2 = new SqliteRoleStore!(dbPath, auditDbPath);
    expect(store2.getPolicyOverride("mode")).toBe("audit");
    store2.close();

    // Reassign store for afterEach cleanup
    store = new SqliteRoleStore!(dbPath, auditDbPath);
  });
});

// ═══════════════════════════════════════════
// SqliteRoleStore resolveRole
// ═══════════════════════════════════════════

const { bootstrapFirstOwner } = await import("../src/core/bootstrap.js");

describe.skipIf(!SqliteRoleStore)("SqliteRoleStore resolveRole", () => {
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

  it("returns owner for superadmin assignment", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");
    expect(store.resolveRole("telegram", "12345")).toBe("owner");
  });

  it("returns admin for admin assignment", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    // Create admin user and assign admin role
    store.ensureUser("telegram:67890");
    store.linkPlatformIdentity("telegram", "67890", "telegram:67890");

    const roles = store.listRoles("default-project");
    const adminRole = roles.find((r) => r.name === "admin" && r.isSystem);
    expect(adminRole).toBeDefined();

    store.assignRole("telegram:67890", adminRole!.id, "project", "default-project");
    expect(store.resolveRole("telegram", "67890")).toBe("admin");
  });

  it("returns unknown for unlinked user", () => {
    expect(store.resolveRole("telegram", "99999")).toBe("unknown");
  });

  it("returns member for user with non-system role", () => {
    bootstrapFirstOwner(store, "telegram:12345", "test");

    // Create a custom role and assign it
    const customRole = store.createRole("default-project", "moderator", []);
    store.ensureUser("telegram:55555");
    store.linkPlatformIdentity("telegram", "55555", "telegram:55555");
    store.assignRole("telegram:55555", customRole.id, "project", "default-project");

    expect(store.resolveRole("telegram", "55555")).toBe("member");
  });
});
