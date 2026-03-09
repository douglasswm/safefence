/**
 * Lightweight HTTP admin API server for SafeFence RBAC management.
 * Uses Node's built-in `http` module — no external dependencies.
 */

import { createServer, type Server } from "node:http";
import type { RoleStore } from "../core/role-store.js";
import type { GuardrailsConfig } from "../core/types.js";
import { createRouter } from "./routes.js";

export interface AdminServerOptions {
  store: RoleStore;
  port?: number;
  host?: string;
  apiKey?: string;
  config?: GuardrailsConfig;
}

export function createAdminServer(options: AdminServerOptions): Server {
  const { store, port = 18790, host = "127.0.0.1", apiKey, config } = options;
  const handleRequest = createRouter();

  if (!apiKey) {
    console.warn("[safefence] Admin API started WITHOUT authentication. All requests will be rejected. Set apiKey to enable access.");
  }

  const server = createServer(async (req, res) => {
    await handleRequest(req, res, { store, apiKey, config });
  });

  server.listen(port, host, () => {
    console.log(`[safefence] Admin API listening on http://${host}:${port}`);
  });

  return server;
}
