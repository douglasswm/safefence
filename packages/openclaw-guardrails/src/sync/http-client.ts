/**
 * HTTP client for SafeFence control plane REST API.
 * Uses native fetch. Handles JWT auth and error mapping.
 */

import type {
  RegisterRequest,
  RegisterResponse,
  HeartbeatRequest,
  HeartbeatResponse,
  PolicySyncResponse,
  RbacSyncResponse,
  AuditBatchRequest,
  AuditBatchResponse,
  MutationBatchRequest,
  MutationBatchResponse,
  SyncAckRequest,
} from "./types.js";

export class ControlPlaneHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    public readonly endpoint: string,
  ) {
    super(`Control plane ${endpoint} returned ${status}: ${body}`);
    this.name = "ControlPlaneHttpError";
  }
}

export interface HttpClientOptions {
  baseUrl: string;
  /** Instance JWT token, set after registration */
  token?: string;
  /** Request timeout in ms (default: 10000) */
  timeoutMs?: number;
}

export class ControlPlaneHttpClient {
  private baseUrl: string;
  private token: string | undefined;
  private timeoutMs: number;

  constructor(opts: HttpClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 10_000;

    // M5: TLS warning for non-localhost
    try {
      const parsed = new URL(this.baseUrl);
      if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
        console.warn(`[safefence] WARNING: Control plane URL "${this.baseUrl}" is not using TLS. Use HTTPS for non-localhost connections.`);
      }
    } catch {
      // Invalid URL will fail on first request
    }
  }

  setToken(token: string): void {
    this.token = token;
  }

  // ── Registration & Lifecycle ──

  async register(req: RegisterRequest): Promise<RegisterResponse> {
    return this.post<RegisterResponse>("/api/v1/sync/register", req);
  }

  async heartbeat(req: HeartbeatRequest): Promise<HeartbeatResponse> {
    return this.post<HeartbeatResponse>("/api/v1/sync/heartbeat", req);
  }

  async deregister(instanceId: string): Promise<void> {
    await this.post("/api/v1/sync/deregister", { instanceId });
  }

  // ── Pull endpoints ──

  async pullPolicies(since?: number): Promise<PolicySyncResponse> {
    const qs = since != null ? `?since=${since}` : "";
    return this.get<PolicySyncResponse>(`/api/v1/sync/policies${qs}`);
  }

  async pullRbac(since?: number): Promise<RbacSyncResponse> {
    const qs = since != null ? `?since=${since}` : "";
    return this.get<RbacSyncResponse>(`/api/v1/sync/rbac${qs}`);
  }

  // ── Push endpoints ──

  async pushAuditBatch(req: AuditBatchRequest): Promise<AuditBatchResponse> {
    return this.post<AuditBatchResponse>("/api/v1/sync/audit/batch", req);
  }

  async pushMutations(req: MutationBatchRequest): Promise<MutationBatchResponse> {
    return this.post<MutationBatchResponse>("/api/v1/sync/mutations", req);
  }

  async ack(req: SyncAckRequest): Promise<void> {
    await this.post("/api/v1/sync/ack", req);
  }

  // ── Internal ──

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchWithTimeout(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.headers(),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ControlPlaneHttpError(res.status, body, path);
    }
    return (await res.json()) as T;
  }

  private async post<T = void>(path: string, body: unknown): Promise<T> {
    const res = await this.fetchWithTimeout(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new ControlPlaneHttpError(res.status, text, path);
    }
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.token) h["Authorization"] = `Bearer ${this.token}`;
    return h;
  }
}
