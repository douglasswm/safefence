/**
 * ConfigRoleStore: backward-compatible adapter that wraps the existing
 * config-based ownerIds/adminIds/toolAllowByRole system into the RoleStore
 * interface. Used when rbacStore is not enabled or not configured.
 *
 * Bot capabilities are treated as unrestricted (default-allow).
 * No audit logging (noop).
 */

import { toolToAction } from "./permissions.js";
import type { RoleStore } from "./role-store.js";
import type {
  AuditEntry,
  BotInstance,
  DualAuthContext,
  EffectivePermissions,
  GuardrailsConfig,
  PermissionCheck,
  PrincipalRole,
  RbacRole,
  RbacRoleAssignment
} from "./types.js";

/** Maps the legacy PrincipalRole to permission sets. */
function roleToPermissions(role: PrincipalRole, config: GuardrailsConfig): PermissionCheck[] {
  const toolNames = config.authorization.toolAllowByRole[role] ?? [];
  const perms: PermissionCheck[] = [];

  for (const tool of toolNames) {
    // Map tool names to permission categories.
    // Legacy tools map to tool_use:<action> permissions.
    const action = toolToAction(tool);
    if (action) {
      perms.push({ category: "tool_use", action });
    }
  }

  // All roles get public data access
  perms.push({ category: "data_access", action: "public" });

  if (role === "owner") {
    // Owners get everything
    perms.push({ category: "tool_use", action: "*" });
    perms.push({ category: "guardrail", action: "configure" });
    perms.push({ category: "data_access", action: "internal" });
    perms.push({ category: "data_access", action: "restricted" });
    perms.push({ category: "data_access", action: "secret" });
    perms.push({ category: "admin", action: "role_manage" });
    perms.push({ category: "admin", action: "role_assign" });
    perms.push({ category: "admin", action: "project_manage" });
    perms.push({ category: "admin", action: "channel_manage" });
    perms.push({ category: "admin", action: "team_manage" });
    perms.push({ category: "admin", action: "bot_manage" });
    perms.push({ category: "budget", action: "view" });
    perms.push({ category: "approval", action: "approve" });
  } else if (role === "admin") {
    perms.push({ category: "data_access", action: "internal" });
    perms.push({ category: "admin", action: "role_assign" });
    perms.push({ category: "budget", action: "view" });
    perms.push({ category: "approval", action: "approve" });
  }

  return perms;
}

// toolToAction is imported from ./permissions.js

function inferRoleFromConfig(
  senderId: string,
  config: GuardrailsConfig
): PrincipalRole {
  if (config.principal.ownerIds.includes(senderId)) return "owner";
  if (config.principal.adminIds.includes(senderId)) return "admin";
  return "member";
}

function permissionMatches(check: PermissionCheck, perm: PermissionCheck): boolean {
  if (perm.category !== check.category) return false;
  if (perm.action === "*") return true;
  return perm.action === check.action;
}

export class ConfigRoleStore implements RoleStore {
  constructor(private readonly config: GuardrailsConfig) {}

  resolveEffective(ctx: DualAuthContext): EffectivePermissions {
    const role = inferRoleFromConfig(ctx.senderId, this.config);
    const userPerms = roleToPermissions(role, this.config);

    return {
      decision: userPerms.length > 0 ? "allow" : "deny",
      userPermissions: userPerms.map((p) => ({ permission: p, effect: "allow" as const })),
      botCapabilities: [], // unrestricted in config mode
      effectivePermissions: userPerms,
      deniedBy: userPerms.length > 0 ? null : "user_rbac"
    };
  }

  checkPermission(
    ctx: DualAuthContext,
    permission: PermissionCheck
  ): { allowed: boolean; deniedBy: "user_rbac" | "bot_capability" | "bot_access_policy" | "both" | null } {
    const role = inferRoleFromConfig(ctx.senderId, this.config);
    const userPerms = roleToPermissions(role, this.config);
    const allowed = userPerms.some((p) => permissionMatches(permission, p));
    return {
      allowed,
      deniedBy: allowed ? null : "user_rbac"
    };
  }

  // Management methods — all noop in config mode
  registerBot(
    _projectId: string,
    _ownerId: string,
    _platform: string,
    _botPlatformId: string,
    _name?: string
  ): BotInstance {
    throw new Error("ConfigRoleStore does not support bot registration. Enable rbacStore.");
  }

  setBotCapability(): void {
    throw new Error("ConfigRoleStore does not support bot capabilities. Enable rbacStore.");
  }

  setBotAccessPolicy(): void {
    throw new Error("ConfigRoleStore does not support bot access policies. Enable rbacStore.");
  }

  createRole(): RbacRole {
    throw new Error("ConfigRoleStore does not support role creation. Enable rbacStore.");
  }

  deleteRole(): void {
    throw new Error("ConfigRoleStore does not support role deletion. Enable rbacStore.");
  }

  grantRolePermission(): void {
    throw new Error("ConfigRoleStore does not support role permission management. Enable rbacStore.");
  }

  revokeRolePermission(): void {
    throw new Error("ConfigRoleStore does not support role permission management. Enable rbacStore.");
  }

  assignRole(): RbacRoleAssignment {
    throw new Error("ConfigRoleStore does not support role assignment. Enable rbacStore.");
  }

  revokeRole(): void {
    throw new Error("ConfigRoleStore does not support role revocation. Enable rbacStore.");
  }

  getBot(): BotInstance | undefined {
    return undefined;
  }

  getBotByPlatform(): BotInstance | undefined {
    return undefined;
  }

  listBots(): BotInstance[] {
    return [];
  }

  getRole(): RbacRole | undefined {
    return undefined;
  }

  listRoles(): RbacRole[] {
    return [];
  }

  getRolePermissions(): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return [];
  }

  getBotCapabilities(): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return [];
  }

  getUserAssignments(): RbacRoleAssignment[] {
    return [];
  }

  ensureUser(): void {
    // noop
  }

  linkPlatformIdentity(): void {
    // noop
  }

  resolveUserId(): string | undefined {
    return undefined;
  }

  ensureProject(): void {
    // noop
  }

  linkChannel(): void {
    // noop
  }

  unlinkChannel(): void {
    // noop
  }

  resolveChannelProject(): string | undefined {
    return undefined;
  }

  logDecision(): void {
    // noop — config mode uses existing JSONL audit sink
  }

  queryAudit(): AuditEntry[] {
    return [];
  }

  close(): void {
    // noop
  }
}
