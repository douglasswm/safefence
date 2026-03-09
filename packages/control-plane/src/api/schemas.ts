/**
 * Zod schemas for sync API request body validation.
 */

import { z } from "zod";
import type { Context } from "hono";

export const registerSchema = z.object({
  orgApiKey: z.string().min(1),
  instanceId: z.string().min(1),
  pluginVersion: z.string().optional(),
  capabilities: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  groupId: z.string().nullable().optional(),
});

export const heartbeatSchema = z.object({
  instanceId: z.string().optional(), // kept for backwards compat, but JWT instanceId is used
  policyVersion: z.number().int(),
  rbacVersion: z.number().int(),
  auditCursor: z.number().int().optional(),
  metrics: z.record(z.number()).nullable().optional(),
});

export const deregisterSchema = z.object({
  instanceId: z.string().optional(), // kept for backwards compat
});

const auditEventSchema = z.object({
  id: z.string().optional(),
  seq: z.number().int(),
  timestamp: z.number(),
  botInstanceId: z.string().nullable().optional(),
  actorUserId: z.string().nullable().optional(),
  actorPlatform: z.string().nullable().optional(),
  actorPlatformId: z.string().nullable().optional(),
  imChannelId: z.string().nullable().optional(),
  eventType: z.string(),
  decision: z.string().nullable().optional(),
  deniedBy: z.string().nullable().optional(),
  permissionCategory: z.string().nullable().optional(),
  permissionAction: z.string().nullable().optional(),
  details: z.record(z.unknown()).nullable().optional(),
  projectId: z.string().nullable().optional(),
  prevHash: z.string().nullable().optional(),
  eventHash: z.string().nullable().optional(),
});

export const auditBatchSchema = z.object({
  instanceId: z.string().optional(), // kept for backwards compat
  events: z.array(auditEventSchema).optional(),
  cursor: z.number().int(),
});

export const ackSchema = z.object({
  instanceId: z.string().optional(), // kept for backwards compat
  policyVersion: z.number().int().optional(),
  rbacVersion: z.number().int().optional(),
});

type ParseSuccess<T> = { success: true; data: T };
type ParseFailure = { success: false; response: Response };

/** Parse and validate a JSON request body against a Zod schema. Returns 400 on failure. */
export async function parseBody<T extends z.ZodTypeAny>(
  c: Context,
  schema: T,
): Promise<ParseSuccess<z.infer<T>> | ParseFailure> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    return { success: false, response: c.json({ error: "Invalid JSON body" }, 400) };
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    return {
      success: false,
      response: c.json({ error: "Validation failed", issues: result.error.issues }, 400),
    };
  }

  return { success: true, data: result.data };
}
