/**
 * SafeFence Control Plane — PostgreSQL schema (Drizzle ORM)
 *
 * Multi-tenant: all tables include org_id for RLS.
 * RLS policies are applied via migrations, not here.
 */

import {
  pgTable,
  text,
  integer,
  bigint,
  boolean,
  timestamp,
  jsonb,
  uniqueIndex,
  index,
  primaryKey,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// ═══════════════════════════════════════════
// Organizations
// ═══════════════════════════════════════════

export const organizations = pgTable("organizations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  apiKeyHash: text("api_key_hash").notNull(),
  apiKeyPrefix: text("api_key_prefix"),
  planTier: text("plan_tier").notNull().default("free"),
  maxInstances: integer("max_instances").notNull().default(5),
  maxAuditRetentionDays: integer("max_audit_retention_days").notNull().default(90),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════
// Instance Groups
// ═══════════════════════════════════════════

export const instanceGroups = pgTable("instance_groups", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_groups_org").on(table.orgId),
]);

// ═══════════════════════════════════════════
// Instances (connected OpenClaw plugins)
// ═══════════════════════════════════════════

export const instances = pgTable("instances", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  groupId: text("group_id").references(() => instanceGroups.id, { onDelete: "set null" }),
  pluginVersion: text("plugin_version"),
  tags: jsonb("tags").$type<string[]>().default([]),
  status: text("status").notNull().default("registered"),
  policyVersion: integer("policy_version").notNull().default(0),
  rbacVersion: integer("rbac_version").notNull().default(0),
  auditCursor: bigint("audit_cursor", { mode: "number" }).notNull().default(0),
  lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
  lastMetrics: jsonb("last_metrics").$type<Record<string, number>>(),
  registeredAt: timestamp("registered_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_instances_org").on(table.orgId),
  index("idx_instances_group").on(table.groupId),
  index("idx_instances_heartbeat").on(table.lastHeartbeatAt),
]);

// ═══════════════════════════════════════════
// Policies (versioned, scoped)
// ═══════════════════════════════════════════

export const policyCurrent = pgTable("policy_current", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  key: text("key").notNull(),
  value: jsonb("value").notNull(),
  scope: text("scope").notNull().default("org"), // org | group | instance
  scopeId: text("scope_id"), // group or instance ID for scoped overrides
  version: integer("version").notNull().default(1),
  updatedBy: text("updated_by"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_policy_unique").on(table.orgId, table.key, table.scope, table.scopeId),
  index("idx_policy_org").on(table.orgId),
]);

export const policyVersions = pgTable("policy_versions", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  policyId: text("policy_id").notNull().references(() => policyCurrent.id, { onDelete: "cascade" }),
  key: text("key").notNull(),
  value: jsonb("value").notNull(),
  scope: text("scope").notNull(),
  scopeId: text("scope_id"),
  version: integer("version").notNull(),
  changedBy: text("changed_by"),
  changedAt: timestamp("changed_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_policy_versions_org").on(table.orgId),
  index("idx_policy_versions_policy").on(table.policyId),
]);

// ═══════════════════════════════════════════
// RBAC (cloud-level)
// ═══════════════════════════════════════════

export const cloudRoles = pgTable("cloud_roles", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  projectId: text("project_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  isSystem: boolean("is_system").notNull().default(false),
  createdBy: text("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cloud_roles_org").on(table.orgId),
  uniqueIndex("idx_cloud_roles_name").on(table.orgId, table.projectId, table.name),
]);

export const cloudRolePermissions = pgTable("cloud_role_permissions", {
  roleId: text("role_id").notNull().references(() => cloudRoles.id, { onDelete: "cascade" }),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  permissionId: text("permission_id").notNull(),
  effect: text("effect").notNull().default("allow"),
}, (table) => [
  primaryKey({ columns: [table.roleId, table.permissionId] }),
  index("idx_cloud_role_perms_org").on(table.orgId),
]);

export const cloudUsers = pgTable("cloud_users", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  displayName: text("display_name"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cloud_users_org").on(table.orgId),
]);

export const cloudPlatformIdentities = pgTable("cloud_platform_identities", {
  platform: text("platform").notNull(),
  platformId: text("platform_id").notNull(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull().references(() => cloudUsers.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  primaryKey({ columns: [table.platform, table.platformId, table.orgId] }),
  index("idx_cloud_identities_user").on(table.userId),
]);

export const cloudRoleAssignments = pgTable("cloud_role_assignments", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull().references(() => cloudUsers.id, { onDelete: "cascade" }),
  roleId: text("role_id").notNull().references(() => cloudRoles.id, { onDelete: "cascade" }),
  scopeType: text("scope_type").notNull().default("project"),
  scopeId: text("scope_id").notNull(),
  botInstanceId: text("bot_instance_id"),
  grantedBy: text("granted_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
}, (table) => [
  index("idx_cloud_assignments_org").on(table.orgId),
  index("idx_cloud_assignments_user").on(table.userId),
]);

export const cloudBots = pgTable("cloud_bots", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  projectId: text("project_id").notNull(),
  ownerId: text("owner_id").notNull(),
  name: text("name"),
  platform: text("platform").notNull(),
  platformBotId: text("platform_bot_id"),
  accessPolicy: text("access_policy").notNull().default("owner_only"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cloud_bots_org").on(table.orgId),
]);

export const cloudBotCapabilities = pgTable("cloud_bot_capabilities", {
  botId: text("bot_id").notNull().references(() => cloudBots.id, { onDelete: "cascade" }),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  permissionId: text("permission_id").notNull(),
  effect: text("effect").notNull().default("allow"),
}, (table) => [
  primaryKey({ columns: [table.botId, table.permissionId] }),
]);

// ═══════════════════════════════════════════
// RBAC Mutations (for delta sync)
// ═══════════════════════════════════════════

export const rbacMutations = pgTable("rbac_mutations", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  version: integer("version").notNull(),
  mutationType: text("mutation_type").notNull(),
  payload: jsonb("payload").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_rbac_mutations_org_version").on(table.orgId, table.version),
]);

// ═══════════════════════════════════════════
// Audit Events
// ═══════════════════════════════════════════

export const auditEvents = pgTable("audit_events", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  instanceId: text("instance_id").notNull(),
  seq: bigint("seq", { mode: "number" }).notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  botInstanceId: text("bot_instance_id"),
  actorUserId: text("actor_user_id"),
  actorPlatform: text("actor_platform"),
  actorPlatformId: text("actor_platform_id"),
  imChannelId: text("im_channel_id"),
  eventType: text("event_type").notNull(),
  decision: text("decision"),
  deniedBy: text("denied_by"),
  permissionCategory: text("permission_category"),
  permissionAction: text("permission_action"),
  details: jsonb("details"),
  projectId: text("project_id"),
  prevHash: text("prev_hash"),
  eventHash: text("event_hash"),
}, (table) => [
  index("idx_audit_org_time").on(table.orgId, table.timestamp),
  index("idx_audit_instance").on(table.instanceId, table.seq),
  index("idx_audit_event_type").on(table.orgId, table.eventType),
]);

// ═══════════════════════════════════════════
// Org-level version counters
// ═══════════════════════════════════════════

export const orgVersions = pgTable("org_versions", {
  orgId: text("org_id").primaryKey().references(() => organizations.id, { onDelete: "cascade" }),
  policyVersion: integer("policy_version").notNull().default(0),
  rbacVersion: integer("rbac_version").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
