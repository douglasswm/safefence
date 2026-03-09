/**
 * Shared types for SafeFence control plane protocol.
 * Used by both the agent-side sync components and the control plane server.
 */

// ═══════════════════════════════════════════
// Instance Identity
// ═══════════════════════════════════════════

export interface InstanceIdentity {
  instanceId: string;
  orgId?: string;
  registeredAt?: number;
}

// ═══════════════════════════════════════════
// Registration
// ═══════════════════════════════════════════

export interface RegisterRequest {
  orgApiKey: string;
  instanceId: string;
  pluginVersion: string;
  capabilities: string[];
  tags?: string[];
  groupId?: string;
}

export interface RegisterResponse {
  instanceToken: string;
  policyVersion: number;
  rbacVersion: number;
  syncIntervalMs: number;
}

// ═══════════════════════════════════════════
// Heartbeat
// ═══════════════════════════════════════════

export interface HeartbeatRequest {
  instanceId: string;
  policyVersion: number;
  rbacVersion: number;
  auditCursor: number;
  metrics: InstanceMetrics;
}

export interface InstanceMetrics {
  totalEvaluations: number;
  denied: number;
  redacted: number;
  avgLatencyMs: number;
  uptimeS: number;
}

export type { HeartbeatStatus } from "@safefence/types";
export { HEARTBEAT_STATUS } from "@safefence/types";

export interface HeartbeatResponse {
  status: import("@safefence/types").HeartbeatStatus;
  forceResync?: boolean;
}

// ═══════════════════════════════════════════
// SSE Events (cloud → agent push notifications)
// ═══════════════════════════════════════════

export type SyncEventType = "policy_changed" | "rbac_changed" | "force_resync" | "revoked";

export interface SyncEvent {
  type: SyncEventType;
  /** Policy key that changed (only for policy_changed) */
  key?: string;
  /** New version number */
  version?: number;
}

// ═══════════════════════════════════════════
// Policy Sync
// ═══════════════════════════════════════════

import type { PolicyScope } from "@safefence/types";
export type { PolicyScope } from "@safefence/types";

export interface PolicyOverrideRecord {
  key: string;
  value: unknown;
  scope: PolicyScope;
  scopeId?: string;
  version: number;
  updatedBy?: string;
  updatedAt: number;
}

export interface PolicySyncResponse {
  policies: PolicyOverrideRecord[];
  version: number;
  isFullSnapshot: boolean;
}

// ═══════════════════════════════════════════
// RBAC Sync
// ═══════════════════════════════════════════

export interface RbacSyncResponse {
  version: number;
  isFullSnapshot: boolean;
  roles: RbacRoleSyncRecord[];
  assignments: RbacAssignmentSyncRecord[];
  users: RbacUserSyncRecord[];
  bots: RbacBotSyncRecord[];
  permissions: RbacPermissionSyncRecord[];
}

export interface RbacRoleSyncRecord {
  id: string;
  projectId: string;
  name: string;
  description?: string;
  isSystem: boolean;
  deleted?: boolean;
}

export interface RbacAssignmentSyncRecord {
  id: string;
  userId: string;
  roleId: string;
  scopeType: "project" | "im_channel";
  scopeId: string;
  botInstanceId?: string;
  grantedBy?: string;
  expiresAt?: number;
  deleted?: boolean;
}

export interface RbacUserSyncRecord {
  id: string;
  displayName?: string;
  platformIdentities: Array<{ platform: string; platformId: string }>;
}

export interface RbacBotSyncRecord {
  id: string;
  projectId: string;
  ownerId: string;
  name?: string;
  platform: string;
  platformBotId?: string;
  accessPolicy: "owner_only" | "project_members" | "explicit";
  deleted?: boolean;
}

export interface RbacPermissionSyncRecord {
  roleId: string;
  permissionId: string;
  effect: "allow" | "deny";
  deleted?: boolean;
}

// ═══════════════════════════════════════════
// Audit Upload
// ═══════════════════════════════════════════

export interface AuditBatchRequest {
  instanceId: string;
  events: AuditUploadEvent[];
  cursor: number;
}

export interface AuditUploadEvent {
  id: string;
  seq: number;
  timestamp: number;
  botInstanceId?: string;
  actorUserId?: string;
  actorPlatform?: string;
  actorPlatformId?: string;
  imChannelId?: string;
  eventType: string;
  decision?: "allow" | "deny";
  deniedBy?: string;
  permissionCategory?: string;
  permissionAction?: string;
  details?: Record<string, unknown>;
  projectId?: string;
  prevHash: string;
  eventHash: string;
}

export interface AuditBatchResponse {
  ackedCursor: number;
}

// ═══════════════════════════════════════════
// Local Mutations (agent → cloud)
// ═══════════════════════════════════════════

export type MutationType =
  | "role_create" | "role_delete"
  | "role_perm_grant" | "role_perm_revoke"
  | "assignment_grant" | "assignment_revoke"
  | "bot_register" | "bot_cap_set" | "bot_access_change"
  | "user_create" | "identity_link"
  | "channel_link" | "channel_unlink"
  | "policy_set" | "policy_delete";

export interface LocalMutation {
  id: string;
  type: MutationType;
  timestamp: number;
  payload: Record<string, unknown>;
}

export interface MutationBatchRequest {
  instanceId: string;
  mutations: LocalMutation[];
}

export interface MutationBatchResponse {
  accepted: number;
  rejected: Array<{ id: string; reason: string }>;
}

// ═══════════════════════════════════════════
// Ack
// ═══════════════════════════════════════════

export interface SyncAckRequest {
  instanceId: string;
  policyVersion?: number;
  rbacVersion?: number;
}
