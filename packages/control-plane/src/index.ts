/**
 * SafeFence Control Plane — Main entry point.
 * Starts the Hono HTTP server with sync and management APIs.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { serve } from "@hono/node-server";
import Redis from "ioredis";
import { createDb } from "./db/connection.js";
import { initJwtSecret } from "./auth/jwt.js";
import { createSyncRoutes } from "./api/sync-routes.js";
import { createManagementRoutes } from "./api/management-routes.js";
import { SseBroadcaster } from "./sync/sse-broadcaster.js";

const PORT = parseInt(process.env.PORT ?? "3100", 10);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET environment variable is required. Exiting.");
  process.exit(1);
}
const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
const DATABASE_URL = process.env.DATABASE_URL;

// Initialize
initJwtSecret(JWT_SECRET);

const db = createDb(DATABASE_URL);
const redis = new Redis(REDIS_URL);
const subRedis = new Redis(REDIS_URL);
const broadcaster = new SseBroadcaster(redis, subRedis);

// Build app
const app = new Hono();
app.use("/*", cors({
  origin: process.env.CORS_ORIGIN ?? "http://localhost:3200",
}));
app.use("/*", logger());

// Health check
app.get("/health", (c) => c.json({ status: "ok", version: "0.1.0" }));

// Mount route groups
const syncRoutes = createSyncRoutes(db, broadcaster);
const managementRoutes = createManagementRoutes(db, broadcaster);

app.route("/api/v1/sync", syncRoutes);
app.route("/api/v1", managementRoutes);

// Start server
console.log(`SafeFence Control Plane starting on port ${PORT}`);
serve({ fetch: app.fetch, port: PORT });
