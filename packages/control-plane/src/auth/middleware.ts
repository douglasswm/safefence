/**
 * Authentication middleware for Hono.
 * Supports two auth modes:
 * 1. API key (for management API) — Bearer sf_...
 * 2. Instance JWT (for sync API) — Bearer eyJ...
 */

import type { Context, Next } from "hono";
import { verifyInstanceToken, type InstanceTokenPayload } from "./jwt.js";
import { resolveOrgByApiKey } from "./api-key.js";
import type { Database } from "../db/connection.js";

declare module "hono" {
  interface ContextVariableMap {
    orgId: string;
    instanceId?: string;
    authMode: "api_key" | "instance_token";
  }
}

export function instanceAuth() {
  return async (c: Context, next: Next) => {
    const auth = c.req.header("Authorization");
    if (!auth?.startsWith("Bearer ")) {
      return c.json({ error: "Missing Authorization header" }, 401);
    }
    const token = auth.slice(7);

    try {
      const payload: InstanceTokenPayload = await verifyInstanceToken(token);
      c.set("orgId", payload.org);
      c.set("instanceId", payload.sub);
      c.set("authMode", "instance_token");
      await next();
    } catch {
      return c.json({ error: "Invalid or expired instance token" }, 401);
    }
  };
}

export function apiKeyAuth(db: Database) {
  return async (c: Context, next: Next) => {
    const auth = c.req.header("Authorization");
    if (!auth?.startsWith("Bearer ")) {
      return c.json({ error: "Missing Authorization header" }, 401);
    }
    const key = auth.slice(7);

    const orgId = await resolveOrgByApiKey(db, key);
    if (orgId) {
      c.set("orgId", orgId);
      c.set("authMode", "api_key");
      await next();
      return;
    }

    return c.json({ error: "Invalid API key" }, 401);
  };
}
