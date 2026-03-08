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
  apiKey?: string;
  config?: GuardrailsConfig;
}

export function createAdminServer(options: AdminServerOptions): Server {
  const { store, port = 18790, apiKey, config } = options;
  const handleRequest = createRouter();

  if (!apiKey) {
    console.warn("[safefence] Admin API started WITHOUT authentication. All requests will be rejected. Set apiKey to enable access.");
  }

  const server = createServer(async (req, res) => {
    // No CORS headers — admin API is not intended for browser access.
    // Clients should call from the same host via curl, CLI, or server-side code.

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    await handleRequest(req, res, { store, apiKey, config });
  });

  server.listen(port, () => {
    console.log(`[safefence] Admin API listening on http://localhost:${port}`);
  });

  return server;
}
