/**
 * SyncRoleStore: Wraps a local RoleStore and queues mutations
 * for upstream sync to the control plane.
 *
 * All reads and writes delegate directly to the underlying store
 * (ensuring local enforcement continues). Mutations are additionally
 * queued for batch upload to the control plane.
 */

import { randomUUID } from "node:crypto";
import type { BootstrapResult } from "../core/bootstrap.js";
import type { RoleStore } from "../core/role-store.js";
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
  RbacRoleAssignment,
} from "../core/types.js";
import type { LocalMutation, MutationType } from "./types.js";

export class SyncRoleStore implements RoleStore {
  private readonly inner: RoleStore;
  private readonly mutationQueue: LocalMutation[] = [];
  private readonly maxQueueSize: number;
  private _queuingEnabled = true;

  constructor(inner: RoleStore, maxQueueSize = 10_000) {
    this.inner = inner;
    this.maxQueueSize = maxQueueSize;
  }

  /** Access the unwrapped inner RoleStore (for sync loops that bypass queuing). */
  get innerStore(): RoleStore {
    return this.inner;
  }

  // ── Mutation queue access ──

  /** Peek at queued mutations without removing them. */
  peekMutations(): readonly LocalMutation[] {
    return this.mutationQueue;
  }

  /** Remove the first `count` mutations from the queue (call after successful push). */
  ackMutations(count: number): void {
    this.mutationQueue.splice(0, count);
  }

  /** Number of pending mutations. */
  get pendingMutationCount(): number {
    return this.mutationQueue.length;
  }

  /** Temporarily disable mutation queuing (for applying remote sync data). */
  withoutQueuing<T>(fn: () => T): T {
    this._queuingEnabled = false;
    try {
      return fn();
    } finally {
      this._queuingEnabled = true;
    }
  }

  private queueMutation(type: MutationType, payload: Record<string, unknown>): void {
    if (!this._queuingEnabled) return;
    if (this.mutationQueue.length >= this.maxQueueSize) {
      console.warn("[safefence] Buffer full, dropping oldest event");
      this.mutationQueue.splice(0, 1);
    }
    this.mutationQueue.push({
      id: randomUUID(),
      type,
      timestamp: Date.now(),
      payload,
    });
  }

  // ── Delegated reads (no mutation queuing) ──

  resolveEffective(ctx: DualAuthContext): EffectivePermissions {
    return this.inner.resolveEffective(ctx);
  }

  checkPermission(ctx: DualAuthContext, permission: PermissionCheck): { allowed: boolean; deniedBy: DeniedBy | null } {
    return this.inner.checkPermission(ctx, permission);
  }

  resolveRole(platform: string, platformId: string): PrincipalRole {
    return this.inner.resolveRole(platform, platformId);
  }

  getBot(botInstanceId: string): BotInstance | undefined {
    return this.inner.getBot(botInstanceId);
  }

  getBotByPlatform(platform: string, platformBotId: string): BotInstance | undefined {
    return this.inner.getBotByPlatform(platform, platformBotId);
  }

  listBots(projectId: string): BotInstance[] {
    return this.inner.listBots(projectId);
  }

  getRole(roleId: string): RbacRole | undefined {
    return this.inner.getRole(roleId);
  }

  listRoles(projectId: string): RbacRole[] {
    return this.inner.listRoles(projectId);
  }

  getRolePermissions(roleId: string): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return this.inner.getRolePermissions(roleId);
  }

  getBotCapabilities(botInstanceId: string): Array<{ permissionId: string; effect: "allow" | "deny" }> {
    return this.inner.getBotCapabilities(botInstanceId);
  }

  getUserAssignments(userId: string): RbacRoleAssignment[] {
    return this.inner.getUserAssignments(userId);
  }

  resolveUserId(platform: string, platformId: string): string | undefined {
    return this.inner.resolveUserId(platform, platformId);
  }

  resolveChannelProject(platform: string, platformChannelId: string): string | undefined {
    return this.inner.resolveChannelProject(platform, platformChannelId);
  }

  hasAnySuperadmin(): boolean {
    return this.inner.hasAnySuperadmin();
  }

  queryAudit(filters: {
    botInstanceId?: string;
    actorUserId?: string;
    eventType?: string;
    projectId?: string;
    since?: number;
    limit?: number;
  }): AuditEntry[] {
    return this.inner.queryAudit(filters);
  }

  getPolicyOverride(key: string): unknown | undefined {
    return this.inner.getPolicyOverride(key);
  }

  getAllPolicyOverrides(): Array<{ key: string; value: unknown; updatedBy?: string; updatedAt: number }> {
    return this.inner.getAllPolicyOverrides();
  }

  // ── Delegated writes + mutation queuing ──

  registerBot(projectId: string, ownerId: string, platform: string, botPlatformId: string, name?: string): BotInstance {
    const bot = this.inner.registerBot(projectId, ownerId, platform, botPlatformId, name);
    this.queueMutation("bot_register", { botId: bot.id, projectId, ownerId, platform, botPlatformId, name });
    return bot;
  }

  setBotCapability(botInstanceId: string, permissionId: string, effect: "allow" | "deny"): void {
    this.inner.setBotCapability(botInstanceId, permissionId, effect);
    this.queueMutation("bot_cap_set", { botInstanceId, permissionId, effect });
  }

  setBotAccessPolicy(botInstanceId: string, policy: "owner_only" | "project_members" | "explicit"): void {
    this.inner.setBotAccessPolicy(botInstanceId, policy);
    this.queueMutation("bot_access_change", { botInstanceId, policy });
  }

  createRole(
    projectId: string,
    name: string,
    permissions: Array<{ permissionId: string; effect: "allow" | "deny" }>,
    description?: string,
    createdBy?: string,
  ): RbacRole {
    const role = this.inner.createRole(projectId, name, permissions, description, createdBy);
    this.queueMutation("role_create", { roleId: role.id, projectId, name, permissions, description, createdBy });
    return role;
  }

  deleteRole(roleId: string): void {
    this.inner.deleteRole(roleId);
    this.queueMutation("role_delete", { roleId });
  }

  grantRolePermission(roleId: string, permissionId: string, effect: "allow" | "deny"): void {
    this.inner.grantRolePermission(roleId, permissionId, effect);
    this.queueMutation("role_perm_grant", { roleId, permissionId, effect });
  }

  revokeRolePermission(roleId: string, permissionId: string): void {
    this.inner.revokeRolePermission(roleId, permissionId);
    this.queueMutation("role_perm_revoke", { roleId, permissionId });
  }

  assignRole(
    userId: string,
    roleId: string,
    scopeType: "project" | "im_channel",
    scopeId: string,
    botInstanceId?: string,
    grantedBy?: string,
    expiresAt?: number,
  ): RbacRoleAssignment {
    const assignment = this.inner.assignRole(userId, roleId, scopeType, scopeId, botInstanceId, grantedBy, expiresAt);
    this.queueMutation("assignment_grant", {
      assignmentId: assignment.id, userId, roleId, scopeType, scopeId, botInstanceId, grantedBy, expiresAt,
    });
    return assignment;
  }

  revokeRole(assignmentId: string): void {
    this.inner.revokeRole(assignmentId);
    this.queueMutation("assignment_revoke", { assignmentId });
  }

  ensureUser(userId: string, displayName?: string): void {
    this.inner.ensureUser(userId, displayName);
    this.queueMutation("user_create", { userId, displayName });
  }

  linkPlatformIdentity(platform: string, platformId: string, userId: string): void {
    this.inner.linkPlatformIdentity(platform, platformId, userId);
    this.queueMutation("identity_link", { platform, platformId, userId });
  }

  ensureProject(projectId: string, orgId: string, name: string): void {
    this.inner.ensureProject(projectId, orgId, name);
    // Projects are managed by the control plane; don't queue
  }

  linkChannel(channelId: string, projectId: string, platform: string, platformChannelId: string, displayName?: string): void {
    this.inner.linkChannel(channelId, projectId, platform, platformChannelId, displayName);
    this.queueMutation("channel_link", { channelId, projectId, platform, platformChannelId, displayName });
  }

  unlinkChannel(platform: string, platformChannelId: string): void {
    this.inner.unlinkChannel(platform, platformChannelId);
    this.queueMutation("channel_unlink", { platform, platformChannelId });
  }

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
  }): void {
    this.inner.logDecision(entry);
  }

  setPolicyOverride(key: string, value: unknown, updatedBy?: string): void {
    this.inner.setPolicyOverride(key, value, updatedBy);
    this.queueMutation("policy_set", { key, value, updatedBy });
  }

  deletePolicyOverride(key: string): void {
    this.inner.deletePolicyOverride(key);
    this.queueMutation("policy_delete", { key });
  }

  bootstrapOwner(senderId: string, source?: string): BootstrapResult {
    return this.inner.bootstrapOwner(senderId, source);
  }

  close(): void {
    this.inner.close();
  }
}
