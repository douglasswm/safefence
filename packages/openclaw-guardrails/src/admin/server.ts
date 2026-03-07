/**
 * Lightweight HTTP admin API server for SafeFence RBAC management.
 * Uses Node's built-in `http` module — no external dependencies.
 */

import { createServer, type Server } from "node:http";
import type { RoleStore } from "../core/role-store.js";
import { createRouter } from "./routes.js";

export interface AdminServerOptions {
  store: RoleStore;
  port?: number;
  apiKey?: string;
}

export function createAdminServer(options: AdminServerOptions): Server {
  const { store, port = 18790, apiKey } = options;
  const handleRequest = createRouter();

  const server = createServer(async (req, res) => {
    // CORS headers for local dev
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    await handleRequest(req, res, { store, apiKey });
  });

  server.listen(port, () => {
    console.log(`[safefence] Admin API listening on http://localhost:${port}`);
  });

  return server;
}
