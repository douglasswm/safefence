/**
 * API client — thin fetch wrapper routing through /api/proxy to avoid CORS.
 */

import type {
  Instance,
  Policy,
  PolicyVersion,
  Role,
  User,
  AuditEvent,
  AuditStats,
} from "./types";

export class ApiClient {
  constructor(
    private orgId: string,
    private apiKey: string,
  ) {}

  private async request<T>(
    path: string,
    options: RequestInit = {},
  ): Promise<T> {
    const res = await fetch(`/api/proxy/${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        ...options.headers,
      },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`API error ${res.status}: ${body}`);
    }
    return res.json();
  }

  private org(path: string) {
    return `orgs/${this.orgId}/${path}`;
  }

  // ── Instances ──
  listInstances(): Promise<Instance[]> {
    return this.request(this.org("instances"));
  }

  deleteInstance(id: string): Promise<{ ok: boolean }> {
    return this.request(this.org(`instances/${id}`), { method: "DELETE" });
  }

  // ── Policies ──
  listPolicies(): Promise<Policy[]> {
    return this.request(this.org("policies"));
  }

  setPolicy(
    key: string,
    value: unknown,
    updatedBy?: string,
  ): Promise<{ key: string; version: number }> {
    return this.request(this.org(`policies/${encodeURIComponent(key)}`), {
      method: "PUT",
      body: JSON.stringify({ value, updatedBy }),
    });
  }

  deletePolicy(key: string): Promise<{ key: string; deleted: boolean; version: number }> {
    return this.request(this.org(`policies/${encodeURIComponent(key)}`), {
      method: "DELETE",
    });
  }

  listPolicyVersions(): Promise<PolicyVersion[]> {
    return this.request(this.org("policies/versions"));
  }

  // ── RBAC: Roles ──
  listRoles(): Promise<Role[]> {
    return this.request(this.org("roles"));
  }

  createRole(name: string, description?: string): Promise<{ id: string; name: string }> {
    return this.request(this.org("roles"), {
      method: "POST",
      body: JSON.stringify({ name, description }),
    });
  }

  deleteRole(roleId: string): Promise<{ ok: boolean }> {
    return this.request(this.org(`roles/${roleId}`), { method: "DELETE" });
  }

  // ── RBAC: Users ──
  listUsers(): Promise<User[]> {
    return this.request(this.org("users"));
  }

  createUser(
    displayName: string,
    platform?: string,
    platformId?: string,
  ): Promise<{ id: string }> {
    return this.request(this.org("users"), {
      method: "POST",
      body: JSON.stringify({ displayName, platform, platformId }),
    });
  }

  // ── RBAC: Assignments ──
  assignRole(
    userId: string,
    roleId: string,
  ): Promise<{ id: string }> {
    return this.request(this.org(`users/${userId}/roles`), {
      method: "POST",
      body: JSON.stringify({ roleId }),
    });
  }

  // ── Audit ──
  listAuditEvents(opts?: {
    limit?: number;
    since?: number;
  }): Promise<AuditEvent[]> {
    const params = new URLSearchParams();
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.since) params.set("since", String(opts.since));
    const qs = params.toString();
    return this.request(this.org(`audit${qs ? `?${qs}` : ""}`));
  }

  getAuditStats(): Promise<AuditStats> {
    return this.request(this.org("audit/stats"));
  }
}
