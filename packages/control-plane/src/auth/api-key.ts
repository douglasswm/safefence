/**
 * API key utilities using bcrypt for hashing.
 */

import { randomBytes } from "node:crypto";
import bcrypt from "bcrypt";
import type { Database } from "../db/connection.js";
import { organizations } from "../db/schema.js";

const SALT_ROUNDS = 12;
const KEY_PREFIX = "sf_";
const KEY_LENGTH = 32;

export function generateApiKey(): string {
  return KEY_PREFIX + randomBytes(KEY_LENGTH).toString("base64url");
}

export async function hashApiKey(key: string): Promise<string> {
  return bcrypt.hash(key, SALT_ROUNDS);
}

export async function verifyApiKey(key: string, hash: string): Promise<boolean> {
  return bcrypt.compare(key, hash);
}

/**
 * Resolve an org ID from an API key by scanning all orgs.
 * TODO: Add api_key_prefix column for O(1) lookup instead of O(n) bcrypt.
 */
export async function resolveOrgByApiKey(db: Database, key: string): Promise<string | null> {
  const orgs = await db.select().from(organizations);
  for (const org of orgs) {
    if (await verifyApiKey(key, org.apiKeyHash)) return org.id;
  }
  return null;
}
