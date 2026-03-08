/**
 * SqliteRoleStore: Full RBAC store backed by SQLite (better-sqlite3).
 *
 * Implements the dual-authorization model:
 *   effective_permission = user_rbac intersection bot_capabilities
 *
 * Schema, seeding, and all management operations live here.
 * Audit logging is delegated to a separate AuditStore (audit.db).
 */

import { randomUUID } from "node:crypto";
import { AuditStore } from "./audit-store.js";
import type { BootstrapResult } from "./bootstrap.js";
import { executeBootstrap } from "./bootstrap.js";
import { MUTABLE_POLICY_KEYS } from "./policy-fields.js";
import type { RoleStore } from "./role-store.js";
import type { Database, DatabaseConstructor, Statement } from "./sqlite-types.js";
import { AUDIT_EVENT_TYPES } from "./types.js";
import type {
  AuditEntry,
  AuditEventType,
  BotInstance,
  DeniedBy,
  DualAuthContext,
  EffectivePermissions,
  GuardrailsConfig,
  PermissionCheck,
  PrincipalRole,
  RbacRole,
  RbacRoleAssignment
} from "./types.js";

// Schema
const RBAC_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  display_name TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_identities (
  platform    TEXT NOT NULL,
  platform_id TEXT NOT NULL,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (platform, platform_id)
);

CREATE TABLE IF NOT EXISTS organisations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_by  TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS im_channels (
  id                  TEXT PRIMARY KEY,
  project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  platform            TEXT NOT NULL,
  platform_channel_id TEXT NOT NULL,
  display_name        TEXT,
  created_at          INTEGER NOT NULL,
  UNIQUE (platform, platform_channel_id)
);

CREATE TABLE IF NOT EXISTS teams (
  id          TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS team_members (
  team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS permissions (
  id          TEXT PRIMARY KEY,
  category    TEXT NOT NULL,
  action      TEXT NOT NULL,
  description TEXT,
  UNIQUE (category, action)
);

CREATE TABLE IF NOT EXISTS permission_groups (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS permission_group_members (
  group_id      TEXT NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, permission_id)
);

CREATE TABLE IF NOT EXISTS bot_instances (
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  owner_id        TEXT NOT NULL REFERENCES users(id),
  name            TEXT,
  platform        TEXT NOT NULL,
  platform_bot_id TEXT,
  account_id      TEXT,
  access_policy   TEXT NOT NULL DEFAULT 'project_members'
                  CHECK (access_policy IN ('owner_only', 'project_members', 'explicit')),
  created_at      INTEGER NOT NULL,
  UNIQUE (platform, platform_bot_id)
);

CREATE TABLE IF NOT EXISTS bot_capabilities (
  bot_instance_id TEXT NOT NULL REFERENCES bot_instances(id) ON DELETE CASCADE,
  permission_id   TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  effect          TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
  PRIMARY KEY (bot_instance_id, permission_id)
);

CREATE TABLE IF NOT EXISTS roles (
  id          TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT,
  is_system   INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT,
  created_at  INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  effect        TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS role_assignments (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id         TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  scope_type      TEXT NOT NULL CHECK (scope_type IN ('project', 'im_channel')),
  scope_id        TEXT NOT NULL,
  bot_instance_id TEXT REFERENCES bot_instances(id) ON DELETE CASCADE,
  granted_by      TEXT,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER,
  UNIQUE (user_id, role_id, scope_type, scope_id, bot_instance_id)
);

CREATE INDEX IF NOT EXISTS idx_role_lookup ON role_assignments(user_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_role_bot_lookup ON role_assignments(user_id, bot_instance_id);

CREATE TABLE IF NOT EXISTS policy_overrides (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_by  TEXT,
  updated_at  INTEGER NOT NULL
);
`;

// System-defined permissions seed data
const SYSTEM_PERMISSIONS: Array<{ id: string; category: string; action: string; description: string }> = [
  { id: "tool_use:read", category: "tool_use", action: "read", description: "Use read-only tools" },
  { id: "tool_use:write", category: "tool_use", action: "write", description: "Use write tools" },
  { id: "tool_use:exec", category: "tool_use", action: "exec", description: "Use tools that run processes" },
  { id: "tool_use:apply_patch", category: "tool_use", action: "apply_patch", description: "Use code patching tools" },
  { id: "tool_use:skills_install", category: "tool_use", action: "skills_install", description: "Install new skills/plugins" },
  { id: "tool_use:*", category: "tool_use", action: "*", description: "All tool operations" },
  { id: "guardrail:enforce", category: "guardrail", action: "enforce", description: "Subject to full guardrail enforcement" },
  { id: "guardrail:audit_only", category: "guardrail", action: "audit_only", description: "Guardrails log but don't block" },
  { id: "guardrail:bypass", category: "guardrail", action: "bypass", description: "Exempt from guardrails" },
  { id: "guardrail:configure", category: "guardrail", action: "configure", description: "Can modify guardrail settings" },
  { id: "data_access:public", category: "data_access", action: "public", description: "Access public data" },
  { id: "data_access:internal", category: "data_access", action: "internal", description: "Access internal data" },
  { id: "data_access:restricted", category: "data_access", action: "restricted", description: "Access restricted data" },
  { id: "data_access:secret", category: "data_access", action: "secret", description: "Access secret data" },
  { id: "budget:view", category: "budget", action: "view", description: "View usage/cost information" },
  { id: "budget:unlimited", category: "budget", action: "unlimited", description: "No rate limits applied" },
  { id: "admin:role_manage", category: "admin", action: "role_manage", description: "Create, edit, delete roles" },
  { id: "admin:role_assign", category: "admin", action: "role_assign", description: "Assign/revoke roles" },
  { id: "admin:project_manage", category: "admin", action: "project_manage", description: "Manage project settings" },
  { id: "admin:channel_manage", category: "admin", action: "channel_manage", description: "Add/remove IM channels" },
  { id: "admin:team_manage", category: "admin", action: "team_manage", description: "Create/edit teams" },
  { id: "admin:bot_manage", category: "admin", action: "bot_manage", description: "Register/configure bot instances" },
  { id: "approval:approve", category: "approval", action: "approve", description: "Can approve restricted actions" },
  { id: "approval:request", category: "approval", action: "request", description: "Can request approval" },
];

const SUPERADMIN_PERMS = SYSTEM_PERMISSIONS.map((p) => p.id);
const ADMIN_PERMS = [
  "tool_use:read", "tool_use:write", "tool_use:exec", "tool_use:apply_patch",
  "data_access:public", "data_access:internal",
  "admin:role_assign", "budget:view", "approval:approve"
];
const VIEWER_PERMS = ["tool_use:read", "data_access:public", "budget:view"];

/** All concrete actions per category for wildcard expansion. */
const CATEGORY_ACTIONS: Record<string, string[]> = {
  tool_use: ["read", "write", "exec", "apply_patch", "skills_install"],
  guardrail: ["enforce", "audit_only", "bypass", "configure"],
  data_access: ["public", "internal", "restricted", "secret"],
  budget: ["view", "unlimited"],
  admin: ["role_manage", "role_assign", "project_manage", "channel_manage", "team_manage", "bot_manage"],
  approval: ["approve", "request"],
};

/** Expand wildcard permissions into concrete ones. */
function expandPerms(
  perms: Array<{ permission: PermissionCheck; effect: "allow" | "deny" }>
): Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> {
  const result: Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> = [];
  for (const p of perms) {
    if (p.permission.action === "*") {
      const actions = CATEGORY_ACTIONS[p.permission.category] ?? [];
      for (const action of actions) {
        result.push({ permission: { category: p.permission.category, action }, effect: p.effect });
      }
    } else {
      result.push(p);
    }
  }
  return result;
}

export class SqliteRoleStore implements RoleStore {
  private db: Database;
  private auditStore: AuditStore;
  private ensuredProjects = new Set<string>();

  // Cached prepared statements for hot-path queries
  private stmtResolveUserId: Statement;
  private stmtGetBotByPlatform: Statement;
  private stmtExplicitAccessCheck: Statement;
  private stmtResolveImChannel: Statement;
  private stmtBotCapabilities: Statement;
  private stmtUserAssignmentsProject: Statement;
  private stmtUserAssignmentsProjectAndChannel: Statement;
  private stmtResolveRoleByUser: Statement;

  constructor(dbPath: string, auditDbPath: string, seedConfig?: GuardrailsConfig) {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const BetterSqlite3 = require("better-sqlite3") as DatabaseConstructor;
    this.db = new BetterSqlite3(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(RBAC_SCHEMA);

    // Prepare hot-path statements once
    this.stmtResolveUserId = this.db.prepare(
      "SELECT user_id FROM platform_identities WHERE platform = ? AND platform_id = ?"
    );
    this.stmtGetBotByPlatform = this.db.prepare(
      "SELECT * FROM bot_instances WHERE platform = ? AND platform_bot_id = ?"
    );
    this.stmtExplicitAccessCheck = this.db.prepare(
      `SELECT 1 FROM role_assignments
       WHERE user_id = ? AND bot_instance_id = ?
       AND (expires_at IS NULL OR expires_at > ?)
       LIMIT 1`
    );
    this.stmtResolveImChannel = this.db.prepare(
      "SELECT id FROM im_channels WHERE platform = ? AND platform_channel_id = ?"
    );
    this.stmtBotCapabilities = this.db.prepare(
      `SELECT p.category, p.action, bc.effect
       FROM bot_capabilities bc
       JOIN permissions p ON p.id = bc.permission_id
       WHERE bc.bot_instance_id = ?`
    );
    this.stmtUserAssignmentsProject = this.db.prepare(
      `SELECT role_id FROM role_assignments
       WHERE user_id = ?
       AND (expires_at IS NULL OR expires_at > ?)
       AND (scope_type = 'project' AND scope_id = ? AND (bot_instance_id IS NULL OR bot_instance_id = ?))`
    );
    this.stmtUserAssignmentsProjectAndChannel = this.db.prepare(
      `SELECT role_id FROM role_assignments
       WHERE user_id = ?
       AND (expires_at IS NULL OR expires_at > ?)
       AND (
         (scope_type = 'project' AND scope_id = ? AND (bot_instance_id IS NULL OR bot_instance_id = ?))
         OR
         (scope_type = 'im_channel' AND scope_id = ? AND (bot_instance_id IS NULL OR bot_instance_id = ?))
       )`
    );

    this.stmtResolveRoleByUser = this.db.prepare(
      `SELECT r.name, r.is_system FROM role_assignments ra
       JOIN roles r ON r.id = ra.role_id
       WHERE ra.user_id = ?
       AND (ra.expires_at IS NULL OR ra.expires_at > ?)`
    );

    this.auditStore = new AuditStore(auditDbPath);
    this.seedPermissions();

    if (seedConfig?.rbacStore?.seedFromConfig) {
      this.seedFromConfig(seedConfig);
    }
  }

  // Seeding

  private seedPermissions(): void {
    const upsert = this.db.prepare(
      "INSERT OR IGNORE INTO permissions (id, category, action, description) VALUES (?, ?, ?, ?)"
    );
    for (const p of SYSTEM_PERMISSIONS) {
      upsert.run(p.id, p.category, p.action, p.description);
    }
  }

  private seedFromConfig(config: GuardrailsConfig): void {
    const orgId = "default-org";
    const projectId = "default-project";

    this.db.prepare(
      "INSERT OR IGNORE INTO organisations (id, name, created_by, created_at) VALUES (?, ?, ?, ?)"
    ).run(orgId, "Default Organisation", null, Date.now());

    this.db.prepare(
      "INSERT OR IGNORE INTO projects (id, org_id, name, created_at) VALUES (?, ?, ?, ?)"
    ).run(projectId, orgId, "Default Project", Date.now());

    this.ensureSystemRoles(projectId);

    for (const ownerId of config.principal.ownerIds) {
      this.ensureUser(ownerId, undefined);
      const superadminRole = this.db.prepare(
        "SELECT id FROM roles WHERE project_id = ? AND name = 'superadmin'"
      ).get(projectId);
      if (superadminRole) {
        this.db.prepare(
          "INSERT OR IGNORE INTO role_assignments (id, user_id, role_id, scope_type, scope_id, bot_instance_id, granted_by, created_at, expires_at) VALUES (?, ?, ?, 'project', ?, NULL, 'system', ?, NULL)"
        ).run(randomUUID(), ownerId, superadminRole.id as string, projectId, Date.now());
      }
    }

    for (const cfgAdminId of config.principal.adminIds) {
      this.ensureUser(cfgAdminId, undefined);
      const adminRole = this.db.prepare(
        "SELECT id FROM roles WHERE project_id = ? AND name = 'admin'"
      ).get(projectId);
      if (adminRole) {
        this.db.prepare(
          "INSERT OR IGNORE INTO role_assignments (id, user_id, role_id, scope_type, scope_id, bot_instance_id, granted_by, created_at, expires_at) VALUES (?, ?, ?, 'project', ?, NULL, 'system', ?, NULL)"
        ).run(randomUUID(), cfgAdminId, adminRole.id as string, projectId, Date.now());
      }
    }
  }

  private ensureSystemRoles(projectId: string): void {
    if (this.ensuredProjects.has(projectId)) return;
    this.ensuredProjects.add(projectId);
    const superadminId = `${projectId}:superadmin`;
    this.db.prepare(
      "INSERT OR IGNORE INTO roles (id, project_id, name, description, is_system, created_by, created_at) VALUES (?, ?, 'superadmin', 'Full control', 1, 'system', ?)"
    ).run(superadminId, projectId, Date.now());

    for (const permId of SUPERADMIN_PERMS) {
      this.db.prepare(
        "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, effect) VALUES (?, ?, 'allow')"
      ).run(superadminId, permId);
    }

    const adminId = `${projectId}:admin`;
    this.db.prepare(
      "INSERT OR IGNORE INTO roles (id, project_id, name, description, is_system, created_by, created_at) VALUES (?, ?, 'admin', 'Administrative access', 1, 'system', ?)"
    ).run(adminId, projectId, Date.now());

    for (const permId of ADMIN_PERMS) {
      this.db.prepare(
        "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, effect) VALUES (?, ?, 'allow')"
      ).run(adminId, permId);
    }

    const viewerId = `${projectId}:viewer`;
    this.db.prepare(
      "INSERT OR IGNORE INTO roles (id, project_id, name, description, is_system, created_by, created_at) VALUES (?, ?, 'viewer', 'Read-only access', 1, 'system', ?)"
    ).run(viewerId, projectId, Date.now());

    for (const permId of VIEWER_PERMS) {
      this.db.prepare(
        "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, effect) VALUES (?, ?, 'allow')"
      ).run(viewerId, permId);
    }
  }

  // Dual-authorization resolution

  resolveEffective(ctx: DualAuthContext): EffectivePermissions {
    const { senderPlatform, senderId, botPlatform, botPlatformId, platformChannelId } = ctx;
    const userId = this.resolveUserId(senderPlatform, senderId);
    const bot = this.getBotByPlatform(botPlatform, botPlatformId);

    if (!userId) {
      return {
        decision: "deny",
        userPermissions: [],
        botCapabilities: [],
        effectivePermissions: [],
        deniedBy: "user_rbac"
      };
    }

    if (!bot) {
      const userPerms = this.resolveUserPermissions(userId);
      return {
        decision: userPerms.length > 0 ? "allow" : "deny",
        userPermissions: userPerms.map((p) => ({ permission: p.permission, effect: p.effect })),
        botCapabilities: [],
        effectivePermissions: userPerms.filter((p) => p.effect === "allow").map((p) => p.permission),
        deniedBy: userPerms.length > 0 ? null : "user_rbac"
      };
    }

    // Bot access policy check
    const accessCheck = this.checkBotAccessPolicy(bot, userId);
    if (!accessCheck.allowed) {
      return {
        decision: "deny",
        userPermissions: [],
        botCapabilities: [],
        effectivePermissions: [],
        deniedBy: "bot_access_policy"
      };
    }

    const projectId = bot.projectId;
    const channelId = platformChannelId
      ? this.resolveImChannelId(botPlatform, platformChannelId)
      : undefined;

    const userPerms = this.resolveUserPermissionsForBot(userId, bot.id, projectId, channelId);
    const botCaps = this.resolveBotCapabilities(bot.id);

    // Expand wildcards and apply deny-overrides
    const expandedUserPerms = expandPerms(userPerms);
    const expandedBotCaps = expandPerms(botCaps);

    const userAllowedSet = new Map<string, PermissionCheck>();
    for (const p of expandedUserPerms) {
      const key = `${p.permission.category}:${p.permission.action}`;
      if (p.effect === "allow") {
        userAllowedSet.set(key, p.permission);
      }
    }
    // Apply user deny-overrides
    for (const p of expandedUserPerms) {
      if (p.effect === "deny") {
        userAllowedSet.delete(`${p.permission.category}:${p.permission.action}`);
      }
    }

    const botDeniedSet = new Set<string>();
    for (const c of expandedBotCaps) {
      if (c.effect === "deny") {
        botDeniedSet.add(`${c.permission.category}:${c.permission.action}`);
      }
    }

    // Intersection: user allowed minus bot denied
    const effective: PermissionCheck[] = [];
    for (const [key, perm] of userAllowedSet) {
      if (!botDeniedSet.has(key)) {
        effective.push(perm);
      }
    }

    let deniedBy: EffectivePermissions["deniedBy"] = null;
    if (userAllowedSet.size === 0 && botDeniedSet.size > 0) {
      deniedBy = "both";
    } else if (userAllowedSet.size === 0) {
      deniedBy = "user_rbac";
    } else if (effective.length < userAllowedSet.size) {
      deniedBy = "bot_capability";
    }

    return {
      decision: effective.length > 0 ? "allow" : "deny",
      userPermissions: userPerms.map((p) => ({ permission: p.permission, effect: p.effect })),
      botCapabilities: botCaps.map((c) => ({ permission: c.permission, effect: c.effect })),
      effectivePermissions: effective,
      deniedBy: effective.length > 0 ? null : (deniedBy ?? "user_rbac")
    };
  }

  checkPermission(
    ctx: DualAuthContext,
    permission: PermissionCheck
  ): { allowed: boolean; deniedBy: EffectivePermissions["deniedBy"] } {
    const { senderPlatform, senderId, botPlatform, botPlatformId, platformChannelId } = ctx;
    const userId = this.resolveUserId(senderPlatform, senderId);
    if (!userId) return { allowed: false, deniedBy: "user_rbac" };

    const bot = this.getBotByPlatform(botPlatform, botPlatformId);

    if (!bot) {
      const userPerms = this.resolveUserPermissions(userId);
      const userHas = this.permsInclude(expandPerms(userPerms), permission);
      return { allowed: userHas, deniedBy: userHas ? null : "user_rbac" };
    }

    // Bot access policy
    const accessCheck = this.checkBotAccessPolicy(bot, userId);
    if (!accessCheck.allowed) return { allowed: false, deniedBy: "bot_access_policy" };

    const projectId = bot.projectId;
    const channelId = platformChannelId
      ? this.resolveImChannelId(botPlatform, platformChannelId)
      : undefined;

    const userPerms = expandPerms(this.resolveUserPermissionsForBot(userId, bot.id, projectId, channelId));
    const botCaps = expandPerms(this.resolveBotCapabilities(bot.id));

    // Check user has the permission (deny-overrides)
    let userAllows = false;
    let userDenies = false;
    for (const p of userPerms) {
      if (p.permission.category === permission.category &&
          (p.permission.action === permission.action || p.permission.action === "*")) {
        if (p.effect === "deny") { userDenies = true; }
        else { userAllows = true; }
      }
    }
    const userHas = userAllows && !userDenies;

    // Check bot capability ceiling
    let botDenies = false;
    for (const c of botCaps) {
      if (c.effect === "deny" &&
          c.permission.category === permission.category &&
          (c.permission.action === permission.action || c.permission.action === "*")) {
        botDenies = true;
        break;
      }
    }

    if (userHas && !botDenies) return { allowed: true, deniedBy: null };
    if (!userHas && botDenies) return { allowed: false, deniedBy: "both" };
    if (!userHas) return { allowed: false, deniedBy: "user_rbac" };
    return { allowed: false, deniedBy: "bot_capability" };
  }

  private permsInclude(
    perms: Array<{ permission: PermissionCheck; effect: "allow" | "deny" }>,
    check: PermissionCheck
  ): boolean {
    let allows = false;
    let denies = false;
    for (const p of perms) {
      if (p.permission.category === check.category &&
          (p.permission.action === check.action || p.permission.action === "*")) {
        if (p.effect === "deny") denies = true;
        else allows = true;
      }
    }
    return allows && !denies;
  }

  // Internal resolution helpers

  private checkBotAccessPolicy(bot: BotInstance, userId: string): { allowed: boolean } {
    switch (bot.accessPolicy) {
      case "owner_only":
        return { allowed: userId === bot.ownerId };
      case "explicit": {
        const row = this.stmtExplicitAccessCheck.get(userId, bot.id, Date.now());
        return { allowed: row !== undefined };
      }
      case "project_members":
      default: {
        // Verify the user has at least one non-expired role assignment in the bot's project
        const memberCheck = this.db.prepare(
          `SELECT 1 FROM role_assignments ra
           JOIN roles r ON r.id = ra.role_id
           WHERE ra.user_id = ? AND r.project_id = ?
           AND (ra.expires_at IS NULL OR ra.expires_at > ?)
           LIMIT 1`
        ).get(userId, bot.projectId, Date.now());
        return { allowed: memberCheck !== undefined };
      }
    }
  }

  private resolveImChannelId(platform: string, platformChannelId: string): string | undefined {
    const row = this.stmtResolveImChannel.get(platform, platformChannelId);
    return row?.id as string | undefined;
  }

  private resolveUserPermissions(
    userId: string
  ): Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> {
    const now = Date.now();
    const assignments = this.db.prepare(
      `SELECT role_id FROM role_assignments
       WHERE user_id = ?
       AND (expires_at IS NULL OR expires_at > ?)`
    ).all(userId, now);

    return this.expandRolePermissions(assignments);
  }

  private resolveUserPermissionsForBot(
    userId: string,
    botInstanceId: string,
    projectId: string,
    channelId?: string
  ): Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> {
    const now = Date.now();

    const assignments = channelId
      ? this.stmtUserAssignmentsProjectAndChannel.all(userId, now, projectId, botInstanceId, channelId, botInstanceId)
      : this.stmtUserAssignmentsProject.all(userId, now, projectId, botInstanceId);

    return this.expandRolePermissions(assignments);
  }

  private expandRolePermissions(
    assignments: Record<string, unknown>[]
  ): Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> {
    if (assignments.length === 0) return [];

    const roleIds = [...new Set(assignments.map((a) => a.role_id as string))];
    const placeholders = roleIds.map(() => "?").join(", ");
    const perms = this.db.prepare(
      `SELECT p.category, p.action, rp.effect
       FROM role_permissions rp
       JOIN permissions p ON p.id = rp.permission_id
       WHERE rp.role_id IN (${placeholders})`
    ).all(...roleIds);

    return perms.map((perm) => ({
      permission: { category: perm.category as string, action: perm.action as string },
      effect: perm.effect as "allow" | "deny"
    }));
  }

  private resolveBotCapabilities(
    botInstanceId: string
  ): Array<{ permission: PermissionCheck; effect: "allow" | "deny" }> {
    const rows = this.stmtBotCapabilities.all(botInstanceId);

    return rows.map((row) => ({
      permission: { category: row.category as string, action: row.action as string },
      effect: row.effect as "allow" | "deny"
    }));
  }

  // Management methods

  registerBot(
    projectId: string,
    ownerId: string,
    platform: string,
    botPlatformId: string,
    name?: string
  ): BotInstance {
    const id = randomUUID();
    const now = Date.now();

    this.db.prepare(
      `INSERT INTO bot_instances (id, project_id, owner_id, name, platform, platform_bot_id, access_policy, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'project_members', ?)`
    ).run(id, projectId, ownerId, name ?? null, platform, botPlatformId, now);

    this.logDecision({
      botInstanceId: id,
      actorUserId: ownerId,
      eventType: AUDIT_EVENT_TYPES.BOT_REGISTER,
      projectId,
      details: { platform, botPlatformId, name }
    });

    return {
      id, projectId, ownerId, name, platform,
      platformBotId: botPlatformId,
      accessPolicy: "project_members",
      createdAt: now
    };
  }

  private assertPermissionExists(permissionId: string): void {
    const exists = this.db.prepare("SELECT 1 FROM permissions WHERE id = ?").get(permissionId);
    if (!exists) {
      throw new Error(`Unknown permission: ${permissionId}. Use a valid permission ID (e.g. tool_use:read).`);
    }
  }

  setBotCapability(botInstanceId: string, permissionId: string, effect: "allow" | "deny"): void {
    this.assertPermissionExists(permissionId);
    this.db.prepare(
      `INSERT INTO bot_capabilities (bot_instance_id, permission_id, effect)
       VALUES (?, ?, ?)
       ON CONFLICT (bot_instance_id, permission_id) DO UPDATE SET effect = excluded.effect`
    ).run(botInstanceId, permissionId, effect);

    this.logDecision({
      botInstanceId,
      eventType: AUDIT_EVENT_TYPES.BOT_CAP_SET,
      details: { permissionId, effect }
    });
  }

  setBotAccessPolicy(botInstanceId: string, policy: "owner_only" | "project_members" | "explicit"): void {
    this.db.prepare("UPDATE bot_instances SET access_policy = ? WHERE id = ?").run(policy, botInstanceId);

    this.logDecision({
      botInstanceId,
      eventType: AUDIT_EVENT_TYPES.BOT_ACCESS_CHANGE,
      details: { policy }
    });
  }

  createRole(
    projectId: string,
    name: string,
    permissions: Array<{ permissionId: string; effect: "allow" | "deny" }>,
    description?: string,
    createdBy?: string
  ): RbacRole {
    const id = randomUUID();
    const now = Date.now();

    this.ensureSystemRoles(projectId);

    this.db.prepare(
      `INSERT INTO roles (id, project_id, name, description, is_system, created_by, created_at)
       VALUES (?, ?, ?, ?, 0, ?, ?)`
    ).run(id, projectId, name, description ?? null, createdBy ?? null, now);

    const insertPerm = this.db.prepare(
      "INSERT INTO role_permissions (role_id, permission_id, effect) VALUES (?, ?, ?)"
    );
    for (const perm of permissions) {
      insertPerm.run(id, perm.permissionId, perm.effect);
    }

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.ROLE_CREATE,
      projectId,
      details: { roleId: id, name, permissions }
    });

    return { id, projectId, name, description, isSystem: false, createdBy, createdAt: now };
  }

  deleteRole(roleId: string): void {
    const role = this.getRole(roleId);
    if (!role) return;
    if (role.isSystem) {
      throw new Error(`Cannot delete system role: ${role.name}`);
    }
    this.db.prepare("DELETE FROM roles WHERE id = ?").run(roleId);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.ROLE_DELETE,
      projectId: role.projectId,
      details: { roleId, roleName: role.name }
    });
  }

  grantRolePermission(roleId: string, permissionId: string, effect: "allow" | "deny"): void {
    this.assertPermissionExists(permissionId);
    this.db.prepare(
      `INSERT INTO role_permissions (role_id, permission_id, effect)
       VALUES (?, ?, ?)
       ON CONFLICT (role_id, permission_id) DO UPDATE SET effect = excluded.effect`
    ).run(roleId, permissionId, effect);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.ROLE_PERM_GRANT,
      details: { roleId, permissionId, effect }
    });
  }

  revokeRolePermission(roleId: string, permissionId: string): void {
    this.db.prepare(
      "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?"
    ).run(roleId, permissionId);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.ROLE_PERM_REVOKE,
      details: { roleId, permissionId }
    });
  }

  assignRole(
    userId: string,
    roleId: string,
    scopeType: "project" | "im_channel",
    scopeId: string,
    botInstanceId?: string,
    grantedBy?: string,
    expiresAt?: number
  ): RbacRoleAssignment {
    const id = randomUUID();
    const now = Date.now();

    this.db.prepare(
      `INSERT INTO role_assignments (id, user_id, role_id, scope_type, scope_id, bot_instance_id, granted_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, userId, roleId, scopeType, scopeId, botInstanceId ?? null, grantedBy ?? null, now, expiresAt ?? null);

    this.logDecision({
      actorUserId: grantedBy,
      eventType: AUDIT_EVENT_TYPES.ASSIGNMENT_GRANT,
      details: { assignmentId: id, userId, roleId, scopeType, scopeId, botInstanceId }
    });

    return { id, userId, roleId, scopeType, scopeId, botInstanceId, grantedBy, createdAt: now, expiresAt };
  }

  revokeRole(assignmentId: string): void {
    // Wrap in transaction to prevent TOCTOU race on last-superadmin check
    this.db.transaction(() => {
      const assignment = this.db.prepare(
        "SELECT * FROM role_assignments WHERE id = ?"
      ).get(assignmentId);

      if (assignment) {
        const role = this.db.prepare("SELECT * FROM roles WHERE id = ?").get(assignment.role_id as string);

        if (role && (role.name as string) === "superadmin" && (role.is_system as number) === 1) {
          const count = this.db.prepare(
            `SELECT COUNT(*) as cnt FROM role_assignments ra
             JOIN roles r ON r.id = ra.role_id
             WHERE r.project_id = ? AND r.name = 'superadmin' AND r.is_system = 1
             AND ra.id != ?`
          ).get(role.project_id as string, assignmentId);

          if ((count?.cnt as number) < 1) {
            throw new Error("Cannot revoke last superadmin role assignment in project");
          }
        }
      }

      this.db.prepare("DELETE FROM role_assignments WHERE id = ?").run(assignmentId);
    })();

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.ASSIGNMENT_REVOKE,
      details: { assignmentId }
    });
  }

  // Query methods

  getBot(botInstanceId: string): BotInstance | undefined {
    const row = this.db.prepare("SELECT * FROM bot_instances WHERE id = ?").get(botInstanceId);
    return row ? this.mapBotRow(row) : undefined;
  }

  getBotByPlatform(platform: string, platformBotId: string): BotInstance | undefined {
    const row = this.stmtGetBotByPlatform.get(platform, platformBotId);
    return row ? this.mapBotRow(row) : undefined;
  }

  listBots(projectId: string): BotInstance[] {
    return this.db.prepare("SELECT * FROM bot_instances WHERE project_id = ?")
      .all(projectId).map((r) => this.mapBotRow(r));
  }

  getRole(roleId: string): RbacRole | undefined {
    const row = this.db.prepare("SELECT * FROM roles WHERE id = ?").get(roleId);
    return row ? this.mapRoleRow(row) : undefined;
  }

  listRoles(projectId: string): RbacRole[] {
    return this.db.prepare("SELECT * FROM roles WHERE project_id = ?")
      .all(projectId).map((r) => this.mapRoleRow(r));
  }

  getRolePermissions(roleId: string): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return this.db.prepare("SELECT permission_id, effect FROM role_permissions WHERE role_id = ?")
      .all(roleId).map((r) => ({
        permissionId: r.permission_id as string,
        effect: r.effect as "allow" | "deny"
      }));
  }

  getBotCapabilities(botInstanceId: string): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return this.db.prepare("SELECT permission_id, effect FROM bot_capabilities WHERE bot_instance_id = ?")
      .all(botInstanceId).map((r) => ({
        permissionId: r.permission_id as string,
        effect: r.effect as "allow" | "deny"
      }));
  }

  getUserAssignments(userId: string): RbacRoleAssignment[] {
    return this.db.prepare("SELECT * FROM role_assignments WHERE user_id = ?")
      .all(userId).map((r) => this.mapAssignmentRow(r));
  }

  // User / identity management

  ensureUser(userId: string, displayName?: string): void {
    this.db.prepare(
      "INSERT OR IGNORE INTO users (id, display_name, created_at) VALUES (?, ?, ?)"
    ).run(userId, displayName ?? null, Date.now());
  }

  linkPlatformIdentity(platform: string, platformId: string, userId: string): void {
    this.db.prepare(
      "INSERT OR REPLACE INTO platform_identities (platform, platform_id, user_id, created_at) VALUES (?, ?, ?, ?)"
    ).run(platform, platformId, userId, Date.now());
  }

  resolveUserId(platform: string, platformId: string): string | undefined {
    const row = this.stmtResolveUserId.get(platform, platformId);
    return row?.user_id as string | undefined;
  }

  resolveRole(platform: string, platformId: string): PrincipalRole {
    const userId = this.resolveUserId(platform, platformId);
    if (!userId) return "unknown";

    const now = Date.now();
    const assignments = this.stmtResolveRoleByUser.all(userId, now) as Array<{ name: string; is_system: number }>;

    if (assignments.length === 0) return "member";

    // superadmin system role → owner
    if (assignments.some((a) => a.name === "superadmin" && a.is_system === 1)) {
      return "owner";
    }

    // admin system role → admin
    if (assignments.some((a) => a.name === "admin" && a.is_system === 1)) {
      return "admin";
    }

    return "member";
  }

  // Project / channel management

  ensureProject(projectId: string, orgId: string, name: string): void {
    this.db.prepare(
      "INSERT OR IGNORE INTO organisations (id, name, created_by, created_at) VALUES (?, ?, NULL, ?)"
    ).run(orgId, name, Date.now());

    this.db.prepare(
      "INSERT OR IGNORE INTO projects (id, org_id, name, created_at) VALUES (?, ?, ?, ?)"
    ).run(projectId, orgId, name, Date.now());

    this.ensureSystemRoles(projectId);
  }

  linkChannel(
    channelId: string,
    projectId: string,
    platform: string,
    platformChannelId: string,
    displayName?: string
  ): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO im_channels (id, project_id, platform, platform_channel_id, display_name, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(channelId, projectId, platform, platformChannelId, displayName ?? null, Date.now());

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.CHANNEL_LINK,
      projectId,
      details: { channelId, platform, platformChannelId, displayName }
    });
  }

  unlinkChannel(platform: string, platformChannelId: string): void {
    this.db.prepare(
      "DELETE FROM im_channels WHERE platform = ? AND platform_channel_id = ?"
    ).run(platform, platformChannelId);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.CHANNEL_UNLINK,
      details: { platform, platformChannelId }
    });
  }

  resolveChannelProject(platform: string, platformChannelId: string): string | undefined {
    const row = this.db.prepare(
      "SELECT project_id FROM im_channels WHERE platform = ? AND platform_channel_id = ?"
    ).get(platform, platformChannelId);
    return row?.project_id as string | undefined;
  }

  // Audit logging (delegates to AuditStore)

  logDecision(entry: {
    botInstanceId?: string;
    actorUserId?: string;
    actorPlatform?: string;
    actorPlatformId?: string;
    imChannelId?: string;
    eventType: string;
    decision?: "allow" | "deny";
    deniedBy?: "user_rbac" | "bot_capability" | "bot_access_policy" | "both" | "guardrail";
    permissionCategory?: string;
    permissionAction?: string;
    details?: Record<string, unknown>;
    projectId?: string;
  }): void {
    this.auditStore.append(entry);
  }

  queryAudit(filters: {
    botInstanceId?: string;
    actorUserId?: string;
    eventType?: string;
    projectId?: string;
    since?: number;
    limit?: number;
  }): AuditEntry[] {
    return this.auditStore.query(filters);
  }

  // Row mappers

  private mapBotRow(row: Record<string, unknown>): BotInstance {
    return {
      id: row.id as string,
      projectId: row.project_id as string,
      ownerId: row.owner_id as string,
      name: row.name as string | undefined,
      platform: row.platform as string,
      platformBotId: row.platform_bot_id as string | undefined,
      accountId: row.account_id as string | undefined,
      accessPolicy: row.access_policy as BotInstance["accessPolicy"],
      createdAt: row.created_at as number
    };
  }

  private mapRoleRow(row: Record<string, unknown>): RbacRole {
    return {
      id: row.id as string,
      projectId: row.project_id as string,
      name: row.name as string,
      description: row.description as string | undefined,
      isSystem: (row.is_system as number) === 1,
      createdBy: row.created_by as string | undefined,
      createdAt: row.created_at as number
    };
  }

  private mapAssignmentRow(row: Record<string, unknown>): RbacRoleAssignment {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      roleId: row.role_id as string,
      scopeType: row.scope_type as "project" | "im_channel",
      scopeId: row.scope_id as string,
      botInstanceId: row.bot_instance_id as string | undefined,
      grantedBy: row.granted_by as string | undefined,
      createdAt: row.created_at as number,
      expiresAt: row.expires_at as number | undefined
    };
  }

  // Policy overrides

  getPolicyOverride(key: string): unknown | undefined {
    const row = this.db.prepare("SELECT value FROM policy_overrides WHERE key = ?").get(key);
    if (!row) return undefined;
    return JSON.parse(row.value as string) as unknown;
  }

  getAllPolicyOverrides(): Array<{ key: string; value: unknown; updatedBy?: string; updatedAt: number }> {
    const rows = this.db.prepare("SELECT * FROM policy_overrides ORDER BY key").all();
    return rows.map((r) => ({
      key: r.key as string,
      value: JSON.parse(r.value as string) as unknown,
      updatedBy: r.updated_by as string | undefined,
      updatedAt: r.updated_at as number
    }));
  }

  setPolicyOverride(key: string, value: unknown, updatedBy?: string): void {
    if (!MUTABLE_POLICY_KEYS.has(key)) {
      throw new Error(`Policy key '${key}' is not a mutable field`);
    }
    const now = Date.now();
    const previousRaw = this.db.prepare("SELECT value FROM policy_overrides WHERE key = ?").get(key);
    const previous = previousRaw ? JSON.parse(previousRaw.value as string) : undefined;

    this.db.prepare(
      "INSERT OR REPLACE INTO policy_overrides (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?)"
    ).run(key, JSON.stringify(value), updatedBy ?? null, now);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.POLICY_SET,
      actorUserId: updatedBy,
      details: { key, value, previous }
    });
  }

  deletePolicyOverride(key: string): void {
    const previousRaw = this.db.prepare("SELECT value, updated_by FROM policy_overrides WHERE key = ?").get(key);
    if (!previousRaw) return;

    this.db.prepare("DELETE FROM policy_overrides WHERE key = ?").run(key);

    this.logDecision({
      eventType: AUDIT_EVENT_TYPES.POLICY_DELETE,
      actorUserId: previousRaw.updated_by as string | undefined,
      details: { key, previous: JSON.parse(previousRaw.value as string) }
    });
  }

  // Bootstrap

  hasAnySuperadmin(): boolean {
    const row = this.db.prepare(
      `SELECT 1 FROM role_assignments ra
       JOIN roles r ON r.id = ra.role_id
       WHERE r.name = 'superadmin' AND r.is_system = 1
       AND (ra.expires_at IS NULL OR ra.expires_at > ?)
       LIMIT 1`
    ).get(Date.now());
    return row !== undefined;
  }

  bootstrapOwner(senderId: string, source?: string): BootstrapResult {
    // Wrap in a transaction so the hasAnySuperadmin check + assignRole
    // are atomic — prevents two concurrent callers from both becoming owner.
    return this.db.transaction(() => {
      return executeBootstrap(this, senderId, source);
    })();
  }

  close(): void {
    this.auditStore.close();
    this.db.close();
  }
}
