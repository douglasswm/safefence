/**
 * API key utilities using bcrypt for hashing.
 */

import { randomBytes } from "node:crypto";
import bcrypt from "bcrypt";
import { eq, isNull } from "drizzle-orm";
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
 * Resolve an org ID from an API key.
 * Uses api_key_prefix for O(1) lookup when available,
 * falls back to sequential scan for legacy orgs without prefix.
 */
export async function resolveOrgByApiKey(db: Database, key: string): Promise<string | null> {
  const prefix = key.slice(0, 8);

  // Fast path: lookup by prefix (typically 0-1 rows)
  const byPrefix = await db.select().from(organizations)
    .where(eq(organizations.apiKeyPrefix, prefix));
  const prefixResults = await Promise.all(
    byPrefix.map(async (org) => (await verifyApiKey(key, org.apiKeyHash)) ? org.id : null),
  );
  const prefixMatch = prefixResults.find(Boolean);
  if (prefixMatch) return prefixMatch;

  // Slow path: sequential scan with short-circuit (bcrypt is CPU-bound,
  // parallel would saturate the libuv thread pool without early exit)
  const legacy = await db.select().from(organizations)
    .where(isNull(organizations.apiKeyPrefix));
  for (const org of legacy) {
    if (await verifyApiKey(key, org.apiKeyHash)) return org.id;
  }
  return null;
}
