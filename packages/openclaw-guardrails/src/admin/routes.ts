/**
 * REST route handlers for the SafeFence admin API.
 * Maps HTTP requests to RoleStore operations.
 */

import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { RoleStore } from "../core/role-store.js";

export interface RouteContext {
  store: RoleStore;
  apiKey?: string;
}

type RouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RouteContext,
  params: Record<string, string>
) => Promise<void>;

interface Route {
  method: string;
  pattern: RegExp;
  paramNames: string[];
  handler: RouteHandler;
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const body = Buffer.concat(chunks).toString("utf-8");
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function checkAuth(req: IncomingMessage, apiKey: string | undefined): boolean {
  if (!apiKey) return true;
  const auth = req.headers.authorization;
  return auth === `Bearer ${apiKey}`;
}

function buildRoutes(): Route[] {
  const routes: Route[] = [];

  function route(method: string, path: string, handler: RouteHandler): void {
    const paramNames: string[] = [];
    const pattern = new RegExp(
      "^" + path.replace(/:(\w+)/g, (_match, name: string) => {
        paramNames.push(name);
        return "([^/]+)";
      }) + "$"
    );
    routes.push({ method, pattern, paramNames, handler });
  }

  // Organisations
  route("POST", "/api/v1/orgs", async (req, res, ctx) => {
    const body = await readBody(req);
    const id = (body.id as string) ?? randomUUID();
    ctx.store.ensureProject(id, id, (body.name as string) ?? "New Org");
    json(res, 201, { id, name: body.name });
  });

  // Projects
  route("POST", "/api/v1/orgs/:orgId/projects", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const id = (body.id as string) ?? randomUUID();
    ctx.store.ensureProject(id, params.orgId, (body.name as string) ?? "New Project");
    json(res, 201, { id, orgId: params.orgId, name: body.name });
  });

  // Bots
  route("POST", "/api/v1/projects/:projectId/bots", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const ownerId = body.ownerId as string;
    const platform = body.platform as string;
    const botPlatformId = body.botPlatformId as string;
    if (!ownerId || !platform || !botPlatformId) {
      json(res, 400, { error: "ownerId, platform, and botPlatformId are required" });
      return;
    }
    ctx.store.ensureUser(ownerId);
    const bot = ctx.store.registerBot(params.projectId, ownerId, platform, botPlatformId, body.name as string | undefined);
    json(res, 201, bot);
  });

  route("PUT", "/api/v1/bots/:botId/capabilities", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const permissionId = body.permissionId as string;
    const effect = body.effect as "allow" | "deny";
    if (!permissionId || !effect) {
      json(res, 400, { error: "permissionId and effect are required" });
      return;
    }
    ctx.store.setBotCapability(params.botId, permissionId, effect);
    json(res, 200, { botId: params.botId, permissionId, effect });
  });

  route("PUT", "/api/v1/bots/:botId/access-policy", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const policy = body.policy as "owner_only" | "project_members" | "explicit";
    if (!policy) {
      json(res, 400, { error: "policy is required" });
      return;
    }
    ctx.store.setBotAccessPolicy(params.botId, policy);
    json(res, 200, { botId: params.botId, policy });
  });

  // Roles
  route("POST", "/api/v1/projects/:projectId/roles", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const name = body.name as string;
    if (!name) {
      json(res, 400, { error: "name is required" });
      return;
    }
    const permissions = (body.permissions ?? []) as Array<{ permissionId: string; effect: "allow" | "deny" }>;
    const role = ctx.store.createRole(params.projectId, name, permissions, body.description as string | undefined);
    json(res, 201, role);
  });

  route("GET", "/api/v1/projects/:projectId/roles", async (_req, res, ctx, params) => {
    const roles = ctx.store.listRoles(params.projectId);
    json(res, 200, roles);
  });

  route("DELETE", "/api/v1/roles/:roleId", async (_req, res, ctx, params) => {
    ctx.store.deleteRole(params.roleId);
    json(res, 204, null);
  });

  route("GET", "/api/v1/roles/:roleId/permissions", async (_req, res, ctx, params) => {
    const perms = ctx.store.getRolePermissions(params.roleId);
    json(res, 200, perms);
  });

  route("PUT", "/api/v1/roles/:roleId/permissions", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const permissionId = body.permissionId as string;
    const effect = (body.effect as "allow" | "deny") ?? "allow";
    if (!permissionId) {
      json(res, 400, { error: "permissionId is required" });
      return;
    }
    ctx.store.grantRolePermission(params.roleId, permissionId, effect);
    json(res, 200, { roleId: params.roleId, permissionId, effect });
  });

  route("DELETE", "/api/v1/roles/:roleId/permissions/:permissionId", async (_req, res, ctx, params) => {
    ctx.store.revokeRolePermission(params.roleId, params.permissionId);
    json(res, 204, null);
  });

  // Role Assignments
  route("POST", "/api/v1/roles/:roleId/assign", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const userId = body.userId as string;
    const scopeType = (body.scopeType as string) ?? "project";
    const scopeId = body.scopeId as string;
    if (!userId || !scopeId) {
      json(res, 400, { error: "userId and scopeId are required" });
      return;
    }
    ctx.store.ensureUser(userId);
    const assignment = ctx.store.assignRole(
      userId, params.roleId,
      scopeType as "project" | "im_channel", scopeId,
      body.botInstanceId as string | undefined,
      body.grantedBy as string | undefined,
      body.expiresAt as number | undefined
    );
    json(res, 201, assignment);
  });

  route("DELETE", "/api/v1/assignments/:assignmentId", async (_req, res, ctx, params) => {
    ctx.store.revokeRole(params.assignmentId);
    json(res, 204, null);
  });

  // Effective Permissions
  route("GET", "/api/v1/effective", async (req, res, ctx) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const userPlatform = url.searchParams.get("userPlatform") ?? "";
    const userId = url.searchParams.get("user") ?? "";
    const botPlatform = url.searchParams.get("botPlatform") ?? "";
    const botId = url.searchParams.get("bot") ?? "";
    const channel = url.searchParams.get("channel") ?? undefined;

    if (!userId || !botId) {
      json(res, 400, { error: "user and bot query params are required" });
      return;
    }

    const result = ctx.store.resolveEffective({
      senderPlatform: userPlatform,
      senderId: userId,
      botPlatform,
      botPlatformId: botId,
      platformChannelId: channel
    });
    json(res, 200, result);
  });

  // Channels
  route("POST", "/api/v1/projects/:projectId/channels", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const platform = body.platform as string;
    const platformChannelId = body.platformChannelId as string;
    if (!platform || !platformChannelId) {
      json(res, 400, { error: "platform and platformChannelId are required" });
      return;
    }
    const id = randomUUID();
    ctx.store.linkChannel(id, params.projectId, platform, platformChannelId, body.displayName as string | undefined);
    json(res, 201, { id, projectId: params.projectId, platform, platformChannelId });
  });

  // Audit
  route("GET", "/api/v1/audit", async (req, res, ctx) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const entries = ctx.store.queryAudit({
      botInstanceId: url.searchParams.get("bot") ?? undefined,
      actorUserId: url.searchParams.get("user") ?? undefined,
      eventType: url.searchParams.get("type") ?? undefined,
      projectId: url.searchParams.get("project") ?? undefined,
      since: url.searchParams.has("since") ? parseInt(url.searchParams.get("since")!, 10) : undefined,
      limit: url.searchParams.has("limit") ? parseInt(url.searchParams.get("limit")!, 10) : undefined,
    });
    json(res, 200, entries);
  });

  route("GET", "/api/v1/audit/bots/:botId", async (_req, res, ctx, params) => {
    const entries = ctx.store.queryAudit({ botInstanceId: params.botId });
    json(res, 200, entries);
  });

  route("GET", "/api/v1/audit/bots/:botId/denials", async (_req, res, ctx, params) => {
    const all = ctx.store.queryAudit({ botInstanceId: params.botId });
    const denials = all.filter((e) => e.decision === "deny");
    json(res, 200, denials);
  });

  // Users / Identity
  route("POST", "/api/v1/users", async (req, res, ctx) => {
    const body = await readBody(req);
    const id = (body.id as string) ?? randomUUID();
    ctx.store.ensureUser(id, body.displayName as string | undefined);
    json(res, 201, { id, displayName: body.displayName });
  });

  route("POST", "/api/v1/users/:userId/identities", async (req, res, ctx, params) => {
    const body = await readBody(req);
    const platform = body.platform as string;
    const platformId = body.platformId as string;
    if (!platform || !platformId) {
      json(res, 400, { error: "platform and platformId are required" });
      return;
    }
    ctx.store.linkPlatformIdentity(platform, platformId, params.userId);
    json(res, 201, { platform, platformId, userId: params.userId });
  });

  return routes;
}

export function createRouter(): (req: IncomingMessage, res: ServerResponse, ctx: RouteContext) => Promise<void> {
  const routes = buildRoutes();

  return async function handleRequest(req, res, ctx) {
    if (!checkAuth(req, ctx.apiKey)) {
      json(res, 401, { error: "Unauthorized" });
      return;
    }

    const method = req.method?.toUpperCase() ?? "GET";
    const pathname = (req.url ?? "/").split("?")[0];

    for (const r of routes) {
      if (r.method !== method) continue;
      const match = r.pattern.exec(pathname);
      if (!match) continue;

      const params: Record<string, string> = {};
      for (let i = 0; i < r.paramNames.length; i++) {
        params[r.paramNames[i]] = decodeURIComponent(match[i + 1]);
      }

      try {
        await r.handler(req, res, ctx, params);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        json(res, 500, { error: message });
      }
      return;
    }

    json(res, 404, { error: "Not found" });
  };
}
