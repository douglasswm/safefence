/**
 * Database connection setup for PostgreSQL via drizzle-orm + postgres.js
 */

import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

export function createDb(connectionString?: string) {
  const url = connectionString ?? process.env.DATABASE_URL ?? "postgresql://localhost:5432/safefence";
  const client = postgres(url);
  return drizzle(client, { schema });
}

export type Database = ReturnType<typeof createDb>;
