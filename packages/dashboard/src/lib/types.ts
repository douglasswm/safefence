/**
 * Dashboard types — mirrors control plane API response shapes.
 * Derived from Drizzle schema at control-plane/src/db/schema.ts.
 */

export type InstanceStatus = "registered" | "active" | "connected" | "disconnected" | "deregistered" | "stale";
export type PolicyScope = "org" | "group" | "instance";
export type AuditDecision = "allow" | "deny";

export const INSTANCE_STATUS = {
  REGISTERED: "registered" as const,
  ACTIVE: "active" as const,
  CONNECTED: "connected" as const,
  DISCONNECTED: "disconnected" as const,
  DEREGISTERED: "deregistered" as const,
  STALE: "stale" as const,
};

export const POLICY_SCOPE = {
  ORG: "org" as const,
  GROUP: "group" as const,
  INSTANCE: "instance" as const,
};

export const AUDIT_DECISION = {
  ALLOW: "allow" as const,
  DENY: "deny" as const,
};

export interface Instance {
  id: string;
  orgId: string;
  groupId: string | null;
  pluginVersion: string | null;
  tags: string[];
  status: InstanceStatus;
  policyVersion: number;
  rbacVersion: number;
  auditCursor: number;
  lastHeartbeatAt: string | null;
  lastMetrics: Record<string, number> | null;
  registeredAt: string;
}

export interface InstanceGroup {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  createdAt: string;
}

export interface Policy {
  id: string;
  orgId: string;
  key: string;
  value: unknown;
  scope: string;
  scopeId: string | null;
  version: number;
  updatedBy: string | null;
  updatedAt: string;
}

export interface PolicyVersion {
  id: string;
  orgId: string;
  policyId: string;
  key: string;
  value: unknown;
  scope: string;
  scopeId: string | null;
  version: number;
  changedBy: string | null;
  changedAt: string;
}

export interface Role {
  id: string;
  orgId: string;
  projectId: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  createdBy: string | null;
  createdAt: string;
}

export interface User {
  id: string;
  orgId: string;
  displayName: string | null;
  createdAt: string;
}

export interface RoleAssignment {
  id: string;
  orgId: string;
  userId: string;
  roleId: string;
  scopeType: string;
  scopeId: string;
  botInstanceId: string | null;
  grantedBy: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export interface AuditEvent {
  id: string;
  orgId: string;
  instanceId: string;
  seq: number;
  timestamp: string;
  botInstanceId: string | null;
  actorUserId: string | null;
  actorPlatform: string | null;
  actorPlatformId: string | null;
  imChannelId: string | null;
  eventType: string;
  decision: string | null;
  deniedBy: string | null;
  permissionCategory: string | null;
  permissionAction: string | null;
  details: unknown;
  projectId: string | null;
  prevHash: string | null;
  eventHash: string | null;
}

export interface AuditStats {
  total: number;
  denied: number;
  allowed: number;
}
