/**
 * Management API routes — dashboard/admin-facing endpoints
 * for organizations, policies, RBAC, instances, and audit.
 */

import { Hono } from "hono";
import { randomUUID } from "node:crypto";
import { eq, and, desc, gte, sql } from "drizzle-orm";
import type { Database } from "../db/connection.js";
import {
  organizations,
  instances,
  instanceGroups,
  policyCurrent,
  policyVersions,
  orgVersions,
  cloudRoles,
  cloudRolePermissions,
  cloudRoleAssignments,
  cloudUsers,
  cloudPlatformIdentities,
  cloudBots,
  rbacMutations,
  auditEvents,
  INSTANCE_STATUS,
  POLICY_SCOPE,
  AUDIT_DECISION,
} from "../db/schema.js";
import { generateApiKey, hashApiKey } from "../auth/api-key.js";
import { apiKeyAuth } from "../auth/middleware.js";
import type { SseBroadcaster } from "../sync/sse-broadcaster.js";

export function createManagementRoutes(db: Database, broadcaster: SseBroadcaster): Hono {
  const app = new Hono();

  // ── Organizations (no auth for create; API key for all others) ──

  app.post("/orgs", async (c) => {
    const body = await c.req.json();
    const id = randomUUID();
    const apiKey = generateApiKey();
    const apiKeyHash = await hashApiKey(apiKey);

    await db.insert(organizations).values({
      id,
      name: body.name ?? "New Organization",
      apiKeyHash,
      apiKeyPrefix: apiKey.slice(0, 8),
      planTier: body.planTier ?? "free",
    });

    // Initialize version counters
    await db.insert(orgVersions).values({ orgId: id });

    return c.json({ id, name: body.name, apiKey }, 201);
  });

  // ── All other routes require API key auth ──
  const authed = new Hono();
  authed.use("/*", apiKeyAuth(db));

  // ── Instances ──
  authed.get("/orgs/:orgId/instances", async (c) => {
    const orgId = c.get("orgId");
    const result = await db.select().from(instances).where(eq(instances.orgId, orgId));
    return c.json(result);
  });

  authed.delete("/orgs/:orgId/instances/:id", async (c) => {
    const instanceId = c.req.param("id");
    await db.update(instances)
      .set({ status: INSTANCE_STATUS.DEREGISTERED })
      .where(eq(instances.id, instanceId));
    // Notify instance
    await broadcaster.publish(c.get("orgId"), { type: "revoked" });
    return c.json({ ok: true });
  });

  // ── Instance Groups ──
  authed.post("/orgs/:orgId/groups", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const id = randomUUID();
    await db.insert(instanceGroups).values({
      id,
      orgId,
      name: body.name ?? "New Group",
      description: body.description,
    });
    return c.json({ id, name: body.name }, 201);
  });

  authed.get("/orgs/:orgId/groups", async (c) => {
    const orgId = c.get("orgId");
    const groups = await db.select().from(instanceGroups).where(eq(instanceGroups.orgId, orgId));
    return c.json(groups);
  });

  // ── Policies ──
  authed.get("/orgs/:orgId/policies", async (c) => {
    const orgId = c.get("orgId");
    const policies = await db.select().from(policyCurrent).where(eq(policyCurrent.orgId, orgId));
    return c.json(policies);
  });

  // Must be registered before parametric :key routes to avoid shadowing
  authed.get("/orgs/:orgId/policies/versions", async (c) => {
    const orgId = c.get("orgId");
    const history = await db.select().from(policyVersions)
      .where(eq(policyVersions.orgId, orgId))
      .orderBy(desc(policyVersions.version))
      .limit(100);
    return c.json(history);
  });

  authed.put("/orgs/:orgId/policies/:key", async (c) => {
    const orgId = c.get("orgId");
    const key = c.req.param("key");
    const body = await c.req.json();

    const result = await db.transaction(async (tx) => {
      const newVersion = await bumpPolicyVersion(tx, orgId);

      const [upserted] = await tx
        .insert(policyCurrent)
        .values({
          id: randomUUID(), orgId, key,
          value: body.value, scope: POLICY_SCOPE.ORG,
          version: newVersion, updatedBy: body.updatedBy,
        })
        .onConflictDoUpdate({
          target: [policyCurrent.orgId, policyCurrent.key, policyCurrent.scope, policyCurrent.scopeId],
          set: { value: body.value, version: newVersion, updatedBy: body.updatedBy, updatedAt: new Date() },
        })
        .returning({ id: policyCurrent.id });

      await tx.insert(policyVersions).values({
        id: randomUUID(), orgId, policyId: upserted.id, key,
        value: body.value, scope: POLICY_SCOPE.ORG,
        version: newVersion, changedBy: body.updatedBy,
      });

      return { key, version: newVersion };
    });

    await broadcaster.publish(orgId, { type: "policy_changed", key, version: result.version });
    return c.json(result);
  });

  authed.delete("/orgs/:orgId/policies/:key", async (c) => {
    const orgId = c.get("orgId");
    const key = c.req.param("key");

    const result = await db.transaction(async (tx) => {
      await tx.delete(policyCurrent).where(
        and(eq(policyCurrent.orgId, orgId), eq(policyCurrent.key, key), eq(policyCurrent.scope, POLICY_SCOPE.ORG))
      );
      const newVersion = await bumpPolicyVersion(tx, orgId);
      return { key, deleted: true, version: newVersion };
    });

    await broadcaster.publish(orgId, { type: "policy_changed", key: result.key, version: result.version });
    return c.json(result);
  });

  // ── RBAC: Roles ──
  authed.post("/orgs/:orgId/roles", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const id = randomUUID();

    await db.insert(cloudRoles).values({
      id,
      orgId,
      projectId: body.projectId ?? "default-project",
      name: body.name,
      description: body.description,
      createdBy: body.createdBy,
    });

    await bumpRbacVersion(db, orgId, broadcaster, "role_create", { roleId: id, name: body.name });

    return c.json({ id, name: body.name }, 201);
  });

  authed.get("/orgs/:orgId/roles", async (c) => {
    const orgId = c.get("orgId");
    const roles = await db.select().from(cloudRoles).where(eq(cloudRoles.orgId, orgId));
    return c.json(roles);
  });

  authed.delete("/orgs/:orgId/roles/:roleId", async (c) => {
    const orgId = c.get("orgId");
    const roleId = c.req.param("roleId");
    await db.delete(cloudRoles).where(and(eq(cloudRoles.id, roleId), eq(cloudRoles.orgId, orgId)));
    await bumpRbacVersion(db, orgId, broadcaster, "role_delete", { roleId });
    return c.json({ ok: true });
  });

  // ── RBAC: Users ──
  authed.post("/orgs/:orgId/users", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const id = body.id ?? randomUUID();
    await db.insert(cloudUsers).values({ id, orgId, displayName: body.displayName });

    if (body.platform && body.platformId) {
      await db.insert(cloudPlatformIdentities).values({
        platform: body.platform,
        platformId: body.platformId,
        orgId,
        userId: id,
      });
    }

    return c.json({ id }, 201);
  });

  authed.get("/orgs/:orgId/users", async (c) => {
    const orgId = c.get("orgId");
    const users = await db.select().from(cloudUsers).where(eq(cloudUsers.orgId, orgId));
    return c.json(users);
  });

  // ── RBAC: Assignments ──
  authed.post("/orgs/:orgId/users/:userId/roles", async (c) => {
    const orgId = c.get("orgId");
    const userId = c.req.param("userId");
    const body = await c.req.json();
    const id = randomUUID();

    await db.insert(cloudRoleAssignments).values({
      id,
      orgId,
      userId,
      roleId: body.roleId,
      scopeType: body.scopeType ?? "project",
      scopeId: body.scopeId ?? "default-project",
      botInstanceId: body.botInstanceId,
      grantedBy: body.grantedBy,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
    });

    await bumpRbacVersion(db, orgId, broadcaster, "assignment_grant", { assignmentId: id, userId, roleId: body.roleId });

    return c.json({ id }, 201);
  });

  // ── Audit ──
  authed.get("/orgs/:orgId/audit", async (c) => {
    const orgId = c.get("orgId");
    const limitRaw = parseInt(c.req.query("limit") ?? "100", 10);
    const limit = Math.min(isNaN(limitRaw) ? 100 : limitRaw, 1000);
    const since = c.req.query("since");

    const sinceTs = since ? parseInt(since, 10) : NaN;
    const whereClause = !isNaN(sinceTs)
      ? and(eq(auditEvents.orgId, orgId), gte(auditEvents.timestamp, new Date(sinceTs)))
      : eq(auditEvents.orgId, orgId);

    const events = await db.select().from(auditEvents)
      .where(whereClause)
      .orderBy(desc(auditEvents.timestamp))
      .limit(limit);

    return c.json(events);
  });

  authed.get("/orgs/:orgId/audit/stats", async (c) => {
    const orgId = c.get("orgId");

    const stats = await db.select({
      total: sql<number>`count(*)`,
      denied: sql<number>`count(*) filter (where decision = ${AUDIT_DECISION.DENY})`,
      allowed: sql<number>`count(*) filter (where decision = ${AUDIT_DECISION.ALLOW})`,
    }).from(auditEvents).where(eq(auditEvents.orgId, orgId));

    return c.json(stats[0] ?? { total: 0, denied: 0, allowed: 0 });
  });

  app.route("/", authed);
  return app;
}

/** Atomically bump policy version via SQL increment, returning the new version. */
async function bumpPolicyVersion(db: Pick<Database, "update">, orgId: string): Promise<number> {
  const result = await db.update(orgVersions)
    .set({
      policyVersion: sql`${orgVersions.policyVersion} + 1`,
      updatedAt: new Date(),
    })
    .where(eq(orgVersions.orgId, orgId))
    .returning({ policyVersion: orgVersions.policyVersion });
  return result[0]?.policyVersion ?? 1;
}

/** Atomically bump RBAC version, record mutation, and publish notification. */
async function bumpRbacVersion(
  db: Pick<Database, "update" | "insert">,
  orgId: string,
  broadcaster: SseBroadcaster,
  mutationType: string,
  payload: Record<string, unknown>,
): Promise<void> {
  const result = await db.update(orgVersions)
    .set({
      rbacVersion: sql`${orgVersions.rbacVersion} + 1`,
      updatedAt: new Date(),
    })
    .where(eq(orgVersions.orgId, orgId))
    .returning({ rbacVersion: orgVersions.rbacVersion });
  const newVersion = result[0]?.rbacVersion ?? 1;

  await db.insert(rbacMutations).values({
    id: randomUUID(),
    orgId,
    version: newVersion,
    mutationType,
    payload,
  });

  await broadcaster.publish(orgId, { type: "rbac_changed", version: newVersion });
}
