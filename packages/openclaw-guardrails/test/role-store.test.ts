import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { ConfigRoleStore } from "../src/core/config-role-store.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";
import type { GuardrailsConfig } from "../src/core/types.js";

// SqliteRoleStore tests require better-sqlite3; skip if not available
let SqliteRoleStore: typeof import("../src/core/sqlite-role-store.js").SqliteRoleStore | undefined;
let AuditStore: typeof import("../src/core/audit-store.js").AuditStore | undefined;

try {
  require("better-sqlite3");
  SqliteRoleStore = (await import("../src/core/sqlite-role-store.js")).SqliteRoleStore;
  AuditStore = (await import("../src/core/audit-store.js")).AuditStore;
} catch {
  // better-sqlite3 not available — SQLite tests will be skipped
}

// ═══════════════════════════════════════════
// ConfigRoleStore tests (always run)
// ═══════════════════════════════════════════

describe("ConfigRoleStore", () => {
  let config: GuardrailsConfig;

  beforeEach(() => {
    config = createDefaultConfig("/tmp/test-workspace");
    config.principal.ownerIds = ["owner-1"];
    config.principal.adminIds = ["admin-1"];
  });

  it("resolves owner permissions", () => {
    const store = new ConfigRoleStore(config);
    const result = store.resolveEffective({ senderPlatform: "test", senderId: "owner-1", botPlatform: "test", botPlatformId: "bot-1" });
    expect(result.decision).toBe("allow");
    expect(result.deniedBy).toBeNull();
    expect(result.effectivePermissions.length).toBeGreaterThan(0);
    expect(result.effectivePermissions).toContainEqual({ category: "tool_use", action: "*" });
  });

  it("resolves admin permissions", () => {
    const store = new ConfigRoleStore(config);
    const result = store.resolveEffective({ senderPlatform: "test", senderId: "admin-1", botPlatform: "test", botPlatformId: "bot-1" });
    expect(result.decision).toBe("allow");
    expect(result.effectivePermissions).toContainEqual({ category: "data_access", action: "internal" });
  });

  it("resolves member permissions (limited)", () => {
    const store = new ConfigRoleStore(config);
    const result = store.resolveEffective({ senderPlatform: "test", senderId: "user-123", botPlatform: "test", botPlatformId: "bot-1" });
    expect(result.decision).toBe("allow");
    expect(result.effectivePermissions).toContainEqual({ category: "tool_use", action: "read" });
    // Member should NOT have write
    const hasWrite = result.effectivePermissions.some(
      (p) => p.category === "tool_use" && p.action === "write"
    );
    expect(hasWrite).toBe(false);
  });

  it("checks specific permission", () => {
    const store = new ConfigRoleStore(config);
    const readCheck = store.checkPermission(
      { senderPlatform: "test", senderId: "user-123", botPlatform: "test", botPlatformId: "bot-1" },
      { category: "tool_use", action: "read" }
    );
    expect(readCheck.allowed).toBe(true);

    const writeCheck = store.checkPermission(
      { senderPlatform: "test", senderId: "user-123", botPlatform: "test", botPlatformId: "bot-1" },
      { category: "tool_use", action: "write" }
    );
    expect(writeCheck.allowed).toBe(false);
    expect(writeCheck.deniedBy).toBe("user_rbac");
  });

  it("throws on management operations", () => {
    const store = new ConfigRoleStore(config);
    expect(() => store.registerBot("p", "o", "t", "b")).toThrow("Enable rbacStore");
    expect(() => store.createRole("p", "r", [])).toThrow("Enable rbacStore");
    expect(() => store.assignRole("u", "r", "project", "p")).toThrow("Enable rbacStore");
  });

  it("returns empty for query methods", () => {
    const store = new ConfigRoleStore(config);
    expect(store.listBots("p")).toEqual([]);
    expect(store.listRoles("p")).toEqual([]);
    expect(store.queryAudit({})).toEqual([]);
    expect(store.getBot("x")).toBeUndefined();
    expect(store.resolveUserId("t", "x")).toBeUndefined();
  });
});

// ═══════════════════════════════════════════
// SqliteRoleStore tests (requires better-sqlite3)
// ═══════════════════════════════════════════

const describeSqlite = SqliteRoleStore ? describe : describe.skip;

describeSqlite("SqliteRoleStore", () => {
  let testDir: string;
  let store: InstanceType<NonNullable<typeof SqliteRoleStore>>;

  beforeEach(() => {
    testDir = join(tmpdir(), `safefence-test-${randomUUID()}`);
    mkdirSync(testDir, { recursive: true });
    store = new SqliteRoleStore!(
      join(testDir, "rbac.db"),
      join(testDir, "audit.db")
    );
  });

  afterEach(() => {
    store.close();
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  // ─── Setup helpers ───

  function setupProject(projectId = "proj-1") {
    store.ensureProject(projectId, "org-1", "Test Project");
    return projectId;
  }

  function setupUser(userId: string, platform: string, platformId: string) {
    store.ensureUser(userId);
    store.linkPlatformIdentity(platform, platformId, userId);
    return userId;
  }

  function setupBot(projectId: string, ownerId: string, platform: string, botPlatformId: string, name?: string) {
    return store.registerBot(projectId, ownerId, platform, botPlatformId, name);
  }

  // ─── Basic CRUD ───

  it("creates and retrieves a project with system roles", () => {
    const projectId = setupProject();
    const roles = store.listRoles(projectId);
    expect(roles.length).toBeGreaterThanOrEqual(2);
    expect(roles.some((r) => r.name === "superadmin" && r.isSystem)).toBe(true);
    expect(roles.some((r) => r.name === "viewer" && r.isSystem)).toBe(true);
  });

  it("registers a bot instance", () => {
    const projectId = setupProject();
    const ownerId = setupUser("alice", "telegram", "alice-tg");
    const bot = setupBot(projectId, ownerId, "telegram", "bot-1", "Alice's Bot");

    expect(bot.id).toBeDefined();
    expect(bot.projectId).toBe(projectId);
    expect(bot.ownerId).toBe(ownerId);
    expect(bot.accessPolicy).toBe("project_members");

    const fetched = store.getBot(bot.id);
    expect(fetched).toBeDefined();
    expect(fetched!.name).toBe("Alice's Bot");

    const byPlatform = store.getBotByPlatform("telegram", "bot-1");
    expect(byPlatform).toBeDefined();
    expect(byPlatform!.id).toBe(bot.id);
  });

  it("creates a custom role with permissions", () => {
    const projectId = setupProject();
    const role = store.createRole(projectId, "moderator", [
      { permissionId: "tool_use:read", effect: "allow" },
      { permissionId: "tool_use:write", effect: "allow" },
      { permissionId: "data_access:public", effect: "allow" },
    ], "Content moderator");

    expect(role.name).toBe("moderator");
    expect(role.isSystem).toBe(false);

    const perms = store.getRolePermissions(role.id);
    expect(perms).toHaveLength(3);
    expect(perms).toContainEqual({ permissionId: "tool_use:read", effect: "allow" });
  });

  it("assigns and revokes roles", () => {
    const projectId = setupProject();
    const userId = setupUser("bob", "telegram", "bob-tg");
    const roles = store.listRoles(projectId);
    const viewerRole = roles.find((r) => r.name === "viewer")!;

    const assignment = store.assignRole(userId, viewerRole.id, "project", projectId);
    expect(assignment.userId).toBe(userId);

    const assignments = store.getUserAssignments(userId);
    expect(assignments).toHaveLength(1);

    store.revokeRole(assignment.id);
    expect(store.getUserAssignments(userId)).toHaveLength(0);
  });

  it("prevents deleting system roles", () => {
    const projectId = setupProject();
    const roles = store.listRoles(projectId);
    const superadmin = roles.find((r) => r.name === "superadmin")!;
    expect(() => store.deleteRole(superadmin.id)).toThrow("Cannot delete system role");
  });

  // ─── Dual-authorization resolution ───

  describe("dual-authorization", () => {
    let projectId: string;
    let aliceId: string;
    let bobId: string;
    let botA: ReturnType<typeof setupBot>;
    let botB: ReturnType<typeof setupBot>;

    beforeEach(() => {
      projectId = setupProject();
      aliceId = setupUser("alice", "telegram", "alice-tg");
      bobId = setupUser("bob", "telegram", "bob-tg");
      botA = setupBot(projectId, aliceId, "telegram", "bot-a", "Alice's Bot");
      botB = setupBot(projectId, bobId, "telegram", "bot-b", "Bob's Bot");
    });

    it("allows member with read role to read via bot", () => {
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(aliceId, viewerRole.id, "project", projectId);

      const result = store.checkPermission(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" },
        { category: "tool_use", action: "read" }
      );
      expect(result.allowed).toBe(true);
    });

    it("denies member without write permission", () => {
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(aliceId, viewerRole.id, "project", projectId);

      const result = store.checkPermission(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" },
        { category: "tool_use", action: "write" }
      );
      expect(result.allowed).toBe(false);
      expect(result.deniedBy).toBe("user_rbac");
    });

    it("denies when bot capability denies even if user has permission", () => {
      // Give alice superadmin (all perms)
      const superadminRole = store.listRoles(projectId).find((r) => r.name === "superadmin")!;
      store.assignRole(aliceId, superadminRole.id, "project", projectId);

      // Bot-B denies exec
      store.setBotCapability(botB.id, "tool_use:exec", "deny");

      const result = store.checkPermission(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" },
        { category: "tool_use", action: "exec" }
      );
      expect(result.allowed).toBe(false);
      expect(result.deniedBy).toBe("bot_capability");
    });

    it("intersection: user has read+write, bot denies write -> only read effective", () => {
      const modRole = store.createRole(projectId, "moderator", [
        { permissionId: "tool_use:read", effect: "allow" },
        { permissionId: "tool_use:write", effect: "allow" },
        { permissionId: "data_access:public", effect: "allow" },
      ]);
      store.assignRole(aliceId, modRole.id, "project", projectId);

      store.setBotCapability(botB.id, "tool_use:write", "deny");

      const effective = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" }
      );
      expect(effective.decision).toBe("allow");
      expect(effective.effectivePermissions).toContainEqual({ category: "tool_use", action: "read" });
      expect(effective.effectivePermissions).not.toContainEqual({ category: "tool_use", action: "write" });
    });

    it("bot access_policy=owner_only denies non-owner", () => {
      store.setBotAccessPolicy(botA.id, "owner_only");
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(bobId, viewerRole.id, "project", projectId);

      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "bob-tg", botPlatform: "telegram", botPlatformId: "bot-a" }
      );
      expect(result.decision).toBe("deny");
      expect(result.deniedBy).toBe("bot_access_policy");
    });

    it("bot access_policy=owner_only allows owner", () => {
      store.setBotAccessPolicy(botA.id, "owner_only");
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(aliceId, viewerRole.id, "project", projectId);

      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-a" }
      );
      expect(result.decision).toBe("allow");
    });

    it("bot access_policy=explicit denies without bot-specific assignment", () => {
      store.setBotAccessPolicy(botB.id, "explicit");
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      // Project-level assignment (not bot-specific)
      store.assignRole(aliceId, viewerRole.id, "project", projectId);

      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" }
      );
      expect(result.decision).toBe("deny");
      expect(result.deniedBy).toBe("bot_access_policy");
    });

    it("bot access_policy=explicit allows with bot-specific assignment", () => {
      store.setBotAccessPolicy(botB.id, "explicit");
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(aliceId, viewerRole.id, "project", projectId, botB.id);

      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-b" }
      );
      expect(result.decision).toBe("allow");
    });

    it("unknown user (no platform_identity) is denied", () => {
      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "unknown-user-tg", botPlatform: "telegram", botPlatformId: "bot-a" }
      );
      expect(result.decision).toBe("deny");
      expect(result.deniedBy).toBe("user_rbac");
    });

    it("expired role assignment is excluded", () => {
      const viewerRole = store.listRoles(projectId).find((r) => r.name === "viewer")!;
      store.assignRole(aliceId, viewerRole.id, "project", projectId, undefined, undefined, Date.now() - 1000);

      const result = store.resolveEffective(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-a" }
      );
      expect(result.decision).toBe("deny");
    });

    it("deny-overrides: conflicting roles, deny wins", () => {
      // Create two roles: one allows write, one denies write
      const allowRole = store.createRole(projectId, "writer", [
        { permissionId: "tool_use:write", effect: "allow" },
        { permissionId: "tool_use:read", effect: "allow" },
        { permissionId: "data_access:public", effect: "allow" },
      ]);
      const denyRole = store.createRole(projectId, "no-write", [
        { permissionId: "tool_use:write", effect: "deny" },
      ]);

      store.assignRole(aliceId, allowRole.id, "project", projectId);
      store.assignRole(aliceId, denyRole.id, "project", projectId);

      const result = store.checkPermission(
        { senderPlatform: "telegram", senderId: "alice-tg", botPlatform: "telegram", botPlatformId: "bot-a" },
        { category: "tool_use", action: "write" }
      );
      expect(result.allowed).toBe(false);
    });
  });

  // ─── Last-superadmin protection ───

  it("prevents revoking last superadmin", () => {
    const projectId = setupProject();
    const userId = setupUser("admin", "telegram", "admin-tg");
    const superadminRole = store.listRoles(projectId).find((r) => r.name === "superadmin")!;
    const assignment = store.assignRole(userId, superadminRole.id, "project", projectId);

    expect(() => store.revokeRole(assignment.id)).toThrow("Cannot revoke last superadmin");
  });

  it("allows revoking superadmin if another exists", () => {
    const projectId = setupProject();
    const user1 = setupUser("admin1", "telegram", "admin1-tg");
    const user2 = setupUser("admin2", "telegram", "admin2-tg");
    const superadminRole = store.listRoles(projectId).find((r) => r.name === "superadmin")!;
    const a1 = store.assignRole(user1, superadminRole.id, "project", projectId);
    store.assignRole(user2, superadminRole.id, "project", projectId);

    // Should succeed since user2 still has superadmin
    expect(() => store.revokeRole(a1.id)).not.toThrow();
  });

  // ─── Channel scoping ───

  it("resolves channel-scoped roles", () => {
    const projectId = setupProject();
    const userId = setupUser("user", "telegram", "user-tg");
    const ownerId = setupUser("owner", "telegram", "owner-tg");
    const bot = setupBot(projectId, ownerId, "telegram", "bot-1");

    store.linkChannel("ch-1", projectId, "telegram", "group-123", "Test Group");

    const modRole = store.createRole(projectId, "channel-mod", [
      { permissionId: "tool_use:read", effect: "allow" },
      { permissionId: "tool_use:write", effect: "allow" },
      { permissionId: "data_access:public", effect: "allow" },
    ]);

    // Channel-scoped assignment
    store.assignRole(userId, modRole.id, "im_channel", "ch-1");

    const result = store.resolveEffective(
      { senderPlatform: "telegram", senderId: "user-tg", botPlatform: "telegram", botPlatformId: "bot-1", platformChannelId: "group-123" }
    );
    expect(result.decision).toBe("allow");
    expect(result.effectivePermissions).toContainEqual({ category: "tool_use", action: "write" });
  });

  // ─── Audit logging ───

  it("logs decisions to audit store", () => {
    const projectId = setupProject();
    const userId = setupUser("user", "telegram", "user-tg");

    store.logDecision({
      actorUserId: userId,
      actorPlatform: "telegram",
      actorPlatformId: "user-tg",
      eventType: "authz.allow",
      decision: "allow",
      projectId,
      permissionCategory: "tool_use",
      permissionAction: "read"
    });

    store.logDecision({
      actorUserId: userId,
      actorPlatform: "telegram",
      actorPlatformId: "user-tg",
      eventType: "authz.deny_user",
      decision: "deny",
      deniedBy: "user_rbac",
      projectId,
      permissionCategory: "tool_use",
      permissionAction: "write"
    });

    const entries = store.queryAudit({ actorUserId: userId });
    expect(entries).toHaveLength(2);
    expect(entries[0].eventType).toBe("authz.deny_user"); // most recent first
    expect(entries[1].eventType).toBe("authz.allow");
  });

  it("bot registration is audited", () => {
    const projectId = setupProject();
    const ownerId = setupUser("owner", "telegram", "owner-tg");
    const bot = setupBot(projectId, ownerId, "telegram", "bot-1");

    const entries = store.queryAudit({ eventType: "bot.register" });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0].botInstanceId).toBe(bot.id);
  });

  // ─── Seeding from config ───

  it("seeds from config with ownerIds/adminIds", () => {
    const seedDir = join(tmpdir(), `safefence-seed-${randomUUID()}`);
    mkdirSync(seedDir, { recursive: true });

    const config = createDefaultConfig("/tmp/test");
    config.principal.ownerIds = ["seed-owner-1"];
    config.principal.adminIds = ["seed-admin-1"];
    config.rbacStore = { enabled: true, seedFromConfig: true };

    const seededStore = new SqliteRoleStore!(
      join(seedDir, "rbac.db"),
      join(seedDir, "audit.db"),
      config
    );

    try {
      // Owner should have a superadmin assignment
      const ownerAssignments = seededStore.getUserAssignments("seed-owner-1");
      expect(ownerAssignments.length).toBeGreaterThanOrEqual(1);
      const superadminAssignment = ownerAssignments.find((a) => {
        const role = seededStore.getRole(a.roleId);
        return role?.name === "superadmin";
      });
      expect(superadminAssignment).toBeDefined();
    } finally {
      seededStore.close();
      rmSync(seedDir, { recursive: true, force: true });
    }
  });
});

// ═══════════════════════════════════════════
// AuditStore tests (requires better-sqlite3)
// ═══════════════════════════════════════════

const describeAudit = AuditStore ? describe : describe.skip;

describeAudit("AuditStore", () => {
  let testDir: string;
  let auditStore: InstanceType<NonNullable<typeof AuditStore>>;

  beforeEach(() => {
    testDir = join(tmpdir(), `safefence-audit-${randomUUID()}`);
    mkdirSync(testDir, { recursive: true });
    auditStore = new AuditStore!(join(testDir, "audit.db"));
  });

  afterEach(() => {
    auditStore.close();
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  it("appends and queries audit entries", () => {
    auditStore.append({
      eventType: "authz.allow",
      decision: "allow",
      actorUserId: "user-1",
      botInstanceId: "bot-1"
    });

    auditStore.append({
      eventType: "authz.deny_user",
      decision: "deny",
      deniedBy: "user_rbac",
      actorUserId: "user-2",
      botInstanceId: "bot-1"
    });

    const all = auditStore.query({});
    expect(all).toHaveLength(2);
  });

  it("maintains hash chain", () => {
    auditStore.append({ eventType: "test.event1" });
    auditStore.append({ eventType: "test.event2" });

    const entries = auditStore.query({ limit: 10 });
    // entries are ordered by seq DESC
    const [second, first] = entries;
    expect(first.prevHash).toBe("0"); // genesis
    expect(second.prevHash).toBe(first.eventHash);
  });

  it("filters by botInstanceId", () => {
    auditStore.append({ eventType: "test", botInstanceId: "bot-a" });
    auditStore.append({ eventType: "test", botInstanceId: "bot-b" });
    auditStore.append({ eventType: "test", botInstanceId: "bot-a" });

    const botAEntries = auditStore.query({ botInstanceId: "bot-a" });
    expect(botAEntries).toHaveLength(2);
  });

  it("respects sequence numbers across restarts", () => {
    const dbPath = join(testDir, "persistent-audit.db");

    const store1 = new AuditStore!(dbPath);
    store1.append({ eventType: "event1" });
    store1.append({ eventType: "event2" });
    const entries1 = store1.query({});
    const lastHash = entries1[0].eventHash;
    store1.close();

    // Reopen
    const store2 = new AuditStore!(dbPath);
    store2.append({ eventType: "event3" });
    const entries2 = store2.query({});
    expect(entries2[0].seq).toBe(3);
    expect(entries2[0].prevHash).toBe(lastHash);
    store2.close();
  });
});
