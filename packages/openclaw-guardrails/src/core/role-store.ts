import type {
  AuditEntry,
  AuditEventType,
  BotInstance,
  DeniedBy,
  DualAuthContext,
  EffectivePermissions,
  PermissionCheck,
  PrincipalRole,
  RbacRole,
  RbacRoleAssignment
} from "./types.js";

export interface RoleStore {
  /**
   * Core: dual-authorization resolution.
   * Resolves effective permissions by intersecting user RBAC with bot capabilities.
   */
  resolveEffective(ctx: DualAuthContext): EffectivePermissions;

  /**
   * Check a specific permission via dual-auth.
   */
  checkPermission(
    ctx: DualAuthContext,
    permission: PermissionCheck
  ): { allowed: boolean; deniedBy: DeniedBy | null };

  /**
   * Resolve a platform user's PrincipalRole from the store.
   * Returns "owner" for superadmin, "admin" for admin-level roles,
   * "member" for any other assigned role, "unknown" if not found.
   */
  resolveRole(platform: string, platformId: string): PrincipalRole;

  // ═══════════════════════════════════════════
  // Management methods
  // ═══════════════════════════════════════════

  registerBot(
    projectId: string,
    ownerId: string,
    platform: string,
    botPlatformId: string,
    name?: string
  ): BotInstance;

  setBotCapability(
    botInstanceId: string,
    permissionId: string,
    effect: "allow" | "deny"
  ): void;

  setBotAccessPolicy(
    botInstanceId: string,
    policy: "owner_only" | "project_members" | "explicit"
  ): void;

  createRole(
    projectId: string,
    name: string,
    permissions: Array<{ permissionId: string; effect: "allow" | "deny" }>,
    description?: string,
    createdBy?: string
  ): RbacRole;

  deleteRole(roleId: string): void;

  grantRolePermission(roleId: string, permissionId: string, effect: "allow" | "deny"): void;
  revokeRolePermission(roleId: string, permissionId: string): void;

  assignRole(
    userId: string,
    roleId: string,
    scopeType: "project" | "im_channel",
    scopeId: string,
    botInstanceId?: string,
    grantedBy?: string,
    expiresAt?: number
  ): RbacRoleAssignment;

  revokeRole(assignmentId: string): void;

  // ═══════════════════════════════════════════
  // Query methods
  // ═══════════════════════════════════════════

  getBot(botInstanceId: string): BotInstance | undefined;
  getBotByPlatform(platform: string, platformBotId: string): BotInstance | undefined;
  listBots(projectId: string): BotInstance[];
  getRole(roleId: string): RbacRole | undefined;
  listRoles(projectId: string): RbacRole[];
  getRolePermissions(roleId: string): Array<{ permissionId: string; effect: "allow" | "deny" }>;
  getBotCapabilities(botInstanceId: string): Array<{ permissionId: string; effect: "allow" | "deny" }>;
  getUserAssignments(userId: string): RbacRoleAssignment[];

  // ═══════════════════════════════════════════
  // User / identity management
  // ═══════════════════════════════════════════

  ensureUser(userId: string, displayName?: string): void;
  linkPlatformIdentity(platform: string, platformId: string, userId: string): void;
  resolveUserId(platform: string, platformId: string): string | undefined;

  // ═══════════════════════════════════════════
  // Project / channel management
  // ═══════════════════════════════════════════

  ensureProject(projectId: string, orgId: string, name: string): void;
  linkChannel(
    channelId: string,
    projectId: string,
    platform: string,
    platformChannelId: string,
    displayName?: string
  ): void;
  unlinkChannel(platform: string, platformChannelId: string): void;
  resolveChannelProject(platform: string, platformChannelId: string): string | undefined;

  // ═══════════════════════════════════════════
  // Audit logging (append-only, separate db)
  // ═══════════════════════════════════════════

  logDecision(entry: {
    botInstanceId?: string;
    actorUserId?: string;
    actorPlatform?: string;
    actorPlatformId?: string;
    imChannelId?: string;
    eventType: AuditEventType | string;
    decision?: "allow" | "deny";
    deniedBy?: DeniedBy;
    permissionCategory?: string;
    permissionAction?: string;
    details?: Record<string, unknown>;
    projectId?: string;
  }): void;

  queryAudit(filters: {
    botInstanceId?: string;
    actorUserId?: string;
    eventType?: string;
    projectId?: string;
    since?: number;
    limit?: number;
  }): AuditEntry[];

  // ═══════════════════════════════════════════
  // Policy overrides (runtime-mutable config)
  // ═══════════════════════════════════════════

  getPolicyOverride(key: string): unknown | undefined;
  getAllPolicyOverrides(): Array<{ key: string; value: unknown; updatedBy?: string; updatedAt: number }>;
  setPolicyOverride(key: string, value: unknown, updatedBy?: string): void;
  deletePolicyOverride(key: string): void;

  // ═══════════════════════════════════════════
  // Bootstrap
  // ═══════════════════════════════════════════

  hasAnySuperadmin(): boolean;

  /**
   * Atomically claim the first owner on a fresh install.
   * On SqliteRoleStore this runs in a transaction to prevent races.
   */
  bootstrapOwner(senderId: string, source?: string): import("./bootstrap.js").BootstrapResult;

  // ═══════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════

  close(): void;
}
