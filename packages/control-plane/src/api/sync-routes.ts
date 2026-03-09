/**
 * Sync API routes — agent-facing endpoints for registration,
 * heartbeat, SSE events, and data pull/push.
 */

import { Hono } from "hono";
import { randomUUID } from "node:crypto";
import { eq, gt, and } from "drizzle-orm";
import type { Database } from "../db/connection.js";
import {
  instances,
  policyCurrent,
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
} from "../db/schema.js";
import { createInstanceToken } from "../auth/jwt.js";
import { resolveOrgByApiKey } from "../auth/api-key.js";
import { instanceAuth } from "../auth/middleware.js";
import type { SseBroadcaster } from "../sync/sse-broadcaster.js";

export function createSyncRoutes(db: Database, broadcaster: SseBroadcaster): Hono {
  const app = new Hono();

  // ── Register ──
  app.post("/register", async (c) => {
    const body = await c.req.json();
    const { orgApiKey, instanceId, pluginVersion, capabilities, tags, groupId } = body;

    if (!orgApiKey || !instanceId) {
      return c.json({ error: "orgApiKey and instanceId are required" }, 400);
    }

    // Verify API key
    const orgId = await resolveOrgByApiKey(db, orgApiKey);
    if (!orgId) {
      return c.json({ error: "Invalid API key" }, 401);
    }

    // Upsert instance
    const existing = await db.select().from(instances).where(eq(instances.id, instanceId));
    if (existing.length === 0) {
      await db.insert(instances).values({
        id: instanceId,
        orgId,
        groupId: groupId ?? null,
        pluginVersion,
        tags: tags ?? [],
        status: INSTANCE_STATUS.CONNECTED,
        registeredAt: new Date(),
        lastHeartbeatAt: new Date(),
      });
    } else {
      await db.update(instances)
        .set({ status: INSTANCE_STATUS.CONNECTED, pluginVersion, tags: tags ?? [], lastHeartbeatAt: new Date(), groupId: groupId ?? null })
        .where(eq(instances.id, instanceId));
    }

    // Get current versions
    const versions = await db.select().from(orgVersions).where(eq(orgVersions.orgId, orgId));
    const policyVersion = versions[0]?.policyVersion ?? 0;
    const rbacVersion = versions[0]?.rbacVersion ?? 0;

    // Create JWT
    const instanceToken = await createInstanceToken(instanceId, orgId);

    return c.json({
      instanceToken,
      policyVersion,
      rbacVersion,
      syncIntervalMs: 30_000,
    });
  });

  // ── Protected routes (require instance JWT) ──
  const authed = new Hono();
  authed.use("/*", instanceAuth());

  // ── Heartbeat ──
  authed.post("/heartbeat", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const { instanceId, policyVersion, rbacVersion, auditCursor, metrics } = body;

    await db.update(instances)
      .set({
        lastHeartbeatAt: new Date(),
        policyVersion,
        rbacVersion,
        auditCursor: auditCursor ?? 0,
        lastMetrics: metrics ?? null,
        status: INSTANCE_STATUS.CONNECTED,
      })
      .where(eq(instances.id, instanceId));

    // Check staleness
    const versions = await db.select().from(orgVersions).where(eq(orgVersions.orgId, orgId));
    const currentPolicy = versions[0]?.policyVersion ?? 0;
    const currentRbac = versions[0]?.rbacVersion ?? 0;

    const policyStale = policyVersion < currentPolicy;
    const rbacStale = rbacVersion < currentRbac;
    const forceResync = policyStale && rbacStale;
    const status = forceResync ? "STALE" : policyStale ? "POLICY_STALE" : rbacStale ? "RBAC_STALE" : "OK";

    return c.json({ status, forceResync });
  });

  // ── Deregister ──
  authed.post("/deregister", async (c) => {
    const body = await c.req.json();
    await db.update(instances)
      .set({ status: INSTANCE_STATUS.DISCONNECTED })
      .where(eq(instances.id, body.instanceId));
    return c.json({ ok: true });
  });

  // ── SSE Events ──
  authed.get("/events", (c) => {
    const orgId = c.get("orgId");
    return broadcaster.handleSseStream(c, orgId);
  });

  // ── Pull Policies ──
  authed.get("/policies", async (c) => {
    const orgId = c.get("orgId");
    const since = c.req.query("since");

    const sinceVersion = since ? parseInt(since, 10) : NaN;
    const policies = !isNaN(sinceVersion)
      ? await db.select().from(policyCurrent).where(
          and(eq(policyCurrent.orgId, orgId), gt(policyCurrent.version, sinceVersion))
        )
      : await db.select().from(policyCurrent).where(eq(policyCurrent.orgId, orgId));

    const versions = await db.select().from(orgVersions).where(eq(orgVersions.orgId, orgId));

    return c.json({
      policies: policies.map((p) => ({
        key: p.key,
        value: p.value,
        scope: p.scope,
        scopeId: p.scopeId,
        version: p.version,
        updatedBy: p.updatedBy,
        updatedAt: p.updatedAt?.getTime() ?? Date.now(),
      })),
      version: versions[0]?.policyVersion ?? 0,
      isFullSnapshot: isNaN(sinceVersion),
    });
  });

  // ── Pull RBAC ──
  authed.get("/rbac", async (c) => {
    const orgId = c.get("orgId");
    const since = c.req.query("since");

    if (since) {
      const sinceRbac = parseInt(since, 10);
      if (isNaN(sinceRbac)) {
        // Invalid since param — fall through to full snapshot below
      } else {
        // Delta: return a full snapshot (agent protocol expects roles/assignments/users/bots/permissions,
        // not raw mutations). This is simpler and correct — agent applies idempotently.
        // Future optimization: filter entities by updatedAt > since.
      }
    }

    // Full snapshot
    const [roles, assignments, users, identities, bots, permissions, versions] = await Promise.all([
      db.select().from(cloudRoles).where(eq(cloudRoles.orgId, orgId)),
      db.select().from(cloudRoleAssignments).where(eq(cloudRoleAssignments.orgId, orgId)),
      db.select().from(cloudUsers).where(eq(cloudUsers.orgId, orgId)),
      db.select().from(cloudPlatformIdentities).where(eq(cloudPlatformIdentities.orgId, orgId)),
      db.select().from(cloudBots).where(eq(cloudBots.orgId, orgId)),
      db.select().from(cloudRolePermissions).where(eq(cloudRolePermissions.orgId, orgId)),
      db.select().from(orgVersions).where(eq(orgVersions.orgId, orgId)),
    ]);

    // Group identities by user
    const identitiesByUser = new Map<string, Array<{ platform: string; platformId: string }>>();
    for (const id of identities) {
      if (!identitiesByUser.has(id.userId)) identitiesByUser.set(id.userId, []);
      identitiesByUser.get(id.userId)!.push({ platform: id.platform, platformId: id.platformId });
    }

    return c.json({
      version: versions[0]?.rbacVersion ?? 0,
      isFullSnapshot: true,
      roles: roles.map((r) => ({
        id: r.id,
        projectId: r.projectId,
        name: r.name,
        description: r.description,
        isSystem: r.isSystem,
      })),
      assignments: assignments.map((a) => ({
        id: a.id,
        userId: a.userId,
        roleId: a.roleId,
        scopeType: a.scopeType,
        scopeId: a.scopeId,
        botInstanceId: a.botInstanceId,
        grantedBy: a.grantedBy,
        expiresAt: a.expiresAt?.getTime(),
      })),
      users: users.map((u) => ({
        id: u.id,
        displayName: u.displayName,
        platformIdentities: identitiesByUser.get(u.id) ?? [],
      })),
      bots: bots.map((b) => ({
        id: b.id,
        projectId: b.projectId,
        ownerId: b.ownerId,
        name: b.name,
        platform: b.platform,
        platformBotId: b.platformBotId,
        accessPolicy: b.accessPolicy,
      })),
      permissions: permissions.map((p) => ({
        roleId: p.roleId,
        permissionId: p.permissionId,
        effect: p.effect,
      })),
    });
  });

  // ── Push Audit Batch ──
  authed.post("/audit/batch", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const { instanceId, events, cursor } = body;

    if (events?.length > 0) {
      await db.insert(auditEvents).values(
        events.map((e: any) => ({
          id: e.id ?? randomUUID(),
          orgId,
          instanceId,
          seq: e.seq,
          timestamp: new Date(e.timestamp),
          botInstanceId: e.botInstanceId ?? null,
          actorUserId: e.actorUserId ?? null,
          actorPlatform: e.actorPlatform ?? null,
          actorPlatformId: e.actorPlatformId ?? null,
          imChannelId: e.imChannelId ?? null,
          eventType: e.eventType,
          decision: e.decision ?? null,
          deniedBy: e.deniedBy ?? null,
          permissionCategory: e.permissionCategory ?? null,
          permissionAction: e.permissionAction ?? null,
          details: e.details ?? null,
          projectId: e.projectId ?? null,
          prevHash: e.prevHash ?? null,
          eventHash: e.eventHash ?? null,
        }))
      );
    }

    // Update instance audit cursor
    await db.update(instances)
      .set({ auditCursor: cursor })
      .where(eq(instances.id, instanceId));

    return c.json({ ackedCursor: cursor });
  });

  // ── Push Mutations ──
  authed.post("/mutations", async (c) => {
    const orgId = c.get("orgId");
    const body = await c.req.json();
    const { mutations } = body;

    // For MVP: just ack mutations (cloud-wins conflict resolution means
    // local mutations are advisory; cloud state is authoritative)
    return c.json({ accepted: mutations?.length ?? 0, rejected: [] });
  });

  // ── Ack ──
  authed.post("/ack", async (c) => {
    const body = await c.req.json();
    const { instanceId, policyVersion, rbacVersion } = body;

    const updates: Record<string, unknown> = {};
    if (policyVersion != null) updates.policyVersion = policyVersion;
    if (rbacVersion != null) updates.rbacVersion = rbacVersion;

    if (Object.keys(updates).length > 0) {
      await db.update(instances).set(updates).where(eq(instances.id, instanceId));
    }

    return c.json({ ok: true });
  });

  app.route("/", authed);
  // Register is unauthenticated (uses orgApiKey in body)
  return app;
}
