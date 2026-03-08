/**
 * ControlPlaneAgent: Orchestrates registration, heartbeat, SSE stream,
 * and sync loops for connecting a SafeFence plugin instance to the
 * centralized control plane.
 */

import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { AuditSink } from "../core/audit-sink.js";
import type { RoleStore } from "../core/role-store.js";
import type { ControlPlaneConfig, GuardrailsConfig } from "../core/types.js";
import { PLUGIN_VERSION } from "../plugin/version.js";
import { ControlPlaneHttpClient } from "./http-client.js";
import { PolicySyncLoop } from "./policy-sync-loop.js";
import { RbacSyncLoop } from "./rbac-sync-loop.js";
import { SseClient } from "./sse-client.js";
import { StreamingAuditSink } from "./streaming-audit-sink.js";
import { SyncRoleStore } from "./sync-role-store.js";
import { toError } from "../utils/args.js";
import type { InstanceIdentity, InstanceMetrics, SyncEvent } from "./types.js";

export interface ControlPlaneAgentOptions {
  controlPlaneConfig: ControlPlaneConfig;
  guardrailsConfig: GuardrailsConfig;
  roleStore: RoleStore;
  auditSink: AuditSink;
  onError?: (error: Error) => void;
  onStatusChange?: (status: AgentStatus) => void;
}

export type AgentStatus = "disconnected" | "connecting" | "connected" | "syncing" | "error";

export class ControlPlaneAgent {
  private readonly config: ControlPlaneConfig;
  private readonly guardrailsConfig: GuardrailsConfig;
  private readonly httpClient: ControlPlaneHttpClient;
  private readonly syncRoleStore: SyncRoleStore;
  private readonly streamingAuditSink: StreamingAuditSink;
  private readonly policySyncLoop: PolicySyncLoop;
  private readonly rbacSyncLoop: RbacSyncLoop;
  private sseClient: SseClient | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private mutationFlushTimer: ReturnType<typeof setInterval> | null = null;
  private instanceId: string;
  private onError?: (error: Error) => void;
  private onStatusChange?: (status: AgentStatus) => void;
  private _status: AgentStatus = "disconnected";
  private startTime = Date.now();
  private totalEvaluations = 0;
  private deniedCount = 0;
  private redactedCount = 0;
  private latencySum = 0;

  constructor(opts: ControlPlaneAgentOptions) {
    this.config = opts.controlPlaneConfig;
    this.guardrailsConfig = opts.guardrailsConfig;
    this.onError = opts.onError;
    this.onStatusChange = opts.onStatusChange;

    // Load or generate instance ID
    this.instanceId = this.loadOrCreateInstanceId();

    // HTTP client
    this.httpClient = new ControlPlaneHttpClient({
      baseUrl: this.config.endpoint,
      timeoutMs: 10_000,
    });

    // Wrap stores
    this.syncRoleStore = new SyncRoleStore(opts.roleStore);
    this.streamingAuditSink = new StreamingAuditSink({
      inner: opts.auditSink,
      httpClient: this.httpClient,
      instanceId: this.instanceId,
      flushIntervalMs: this.config.auditFlushIntervalMs ?? 5000,
      batchSize: this.config.auditBatchSize ?? 500,
      onError: (err) => this.handleError(err),
    });

    // Sync loops
    this.policySyncLoop = new PolicySyncLoop({
      httpClient: this.httpClient,
      roleStore: this.syncRoleStore,
      config: this.guardrailsConfig,
      onError: (err) => this.handleError(err),
    });

    this.rbacSyncLoop = new RbacSyncLoop({
      httpClient: this.httpClient,
      roleStore: this.syncRoleStore,
      onError: (err) => this.handleError(err),
    });
  }

  /** Get the wrapped RoleStore (use this in place of the original). */
  get roleStore(): SyncRoleStore {
    return this.syncRoleStore;
  }

  /** Get the wrapped AuditSink (use this in place of the original). */
  get auditSink(): StreamingAuditSink {
    return this.streamingAuditSink;
  }

  get status(): AgentStatus {
    return this._status;
  }

  /** Start the agent: register, sync, connect SSE, start heartbeat. */
  async start(): Promise<void> {
    this.setStatus("connecting");

    try {
      // 1. Register with control plane
      const reg = await this.httpClient.register({
        orgApiKey: this.config.orgApiKey,
        instanceId: this.instanceId,
        pluginVersion: PLUGIN_VERSION,
        capabilities: ["policy_sync", "rbac_sync", "audit_upload"],
        tags: this.config.tags,
        groupId: this.config.groupId,
      });

      this.httpClient.setToken(reg.instanceToken);

      // 2. Full sync on startup
      this.setStatus("syncing");
      await Promise.all([
        this.policySyncLoop.pull(true),
        this.rbacSyncLoop.pull(true),
      ]);

      // 3. Open SSE stream
      const sseUrl = `${this.config.endpoint.replace(/\/$/, "")}/api/v1/sync/events`;
      this.sseClient = new SseClient({
        url: sseUrl,
        token: reg.instanceToken,
        onEvent: (event: SyncEvent) => this.handleSseEvent(event),
        onError: (err) => this.handleError(err),
        onConnect: () => this.setStatus("connected"),
      });
      this.sseClient.start();

      // 4. Start heartbeat
      const heartbeatInterval = this.config.heartbeatIntervalMs ?? 30_000;
      this.heartbeatTimer = setInterval(() => {
        this.sendHeartbeat().catch((err) => this.handleError(toError(err)));
      }, heartbeatInterval);

      // 5. Start audit flush
      this.streamingAuditSink.start();

      // 6. Start mutation flush
      const syncInterval = this.config.syncIntervalMs ?? 30_000;
      this.mutationFlushTimer = setInterval(() => {
        this.flushMutations().catch((err) => this.handleError(toError(err)));
      }, syncInterval);

      this.setStatus("connected");
    } catch (err: unknown) {
      this.setStatus("error");
      throw err;
    }
  }

  /** Graceful shutdown. */
  async stop(): Promise<void> {
    // Stop timers
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.mutationFlushTimer) {
      clearInterval(this.mutationFlushTimer);
      this.mutationFlushTimer = null;
    }

    // Stop SSE
    this.sseClient?.stop();

    // Final flush
    this.streamingAuditSink.stop();
    await this.streamingAuditSink.flush().catch(() => {});
    await this.flushMutations().catch(() => {});

    // Deregister
    try {
      await this.httpClient.deregister(this.instanceId);
    } catch {
      // Best effort
    }

    this.setStatus("disconnected");
  }

  /** Record an evaluation metric for heartbeat reporting. */
  recordEvaluation(decision: "ALLOW" | "DENY" | "REDACT", elapsedMs: number): void {
    this.totalEvaluations++;
    if (decision === "DENY") this.deniedCount++;
    if (decision === "REDACT") this.redactedCount++;
    this.latencySum += elapsedMs;
  }

  // ── Internal ──

  private async handleSseEvent(event: SyncEvent): Promise<void> {
    if (event.type === "revoked") {
      this.setStatus("error");
      await this.stop();
      return;
    }
    await Promise.all([
      this.policySyncLoop.handleEvent(event),
      this.rbacSyncLoop.handleEvent(event),
    ]);
  }

  private async sendHeartbeat(): Promise<void> {
    const metrics: InstanceMetrics = {
      totalEvaluations: this.totalEvaluations,
      denied: this.deniedCount,
      redacted: this.redactedCount,
      avgLatencyMs: this.totalEvaluations > 0 ? this.latencySum / this.totalEvaluations : 0,
      uptimeS: Math.floor((Date.now() - this.startTime) / 1000),
    };

    const response = await this.httpClient.heartbeat({
      instanceId: this.instanceId,
      policyVersion: this.policySyncLoop.policyVersion,
      rbacVersion: this.rbacSyncLoop.rbacVersion,
      auditCursor: this.streamingAuditSink.auditCursor,
      metrics,
    });

    if (response.forceResync) {
      await Promise.all([
        this.policySyncLoop.pull(true),
        this.rbacSyncLoop.pull(true),
      ]);
    }

    if (response.status === "STALE") {
      await Promise.all([this.policySyncLoop.pull(), this.rbacSyncLoop.pull()]);
    } else if (response.status === "POLICY_STALE") {
      await this.policySyncLoop.pull();
    } else if (response.status === "RBAC_STALE") {
      await this.rbacSyncLoop.pull();
    } else if (response.status === "REVOKED") {
      this.setStatus("error");
      await this.stop();
    }
  }

  private async flushMutations(): Promise<void> {
    const mutations = this.syncRoleStore.peekMutations();
    if (mutations.length === 0) return;

    try {
      await this.httpClient.pushMutations({
        instanceId: this.instanceId,
        mutations: [...mutations],
      });
      // Only remove after successful push
      this.syncRoleStore.ackMutations(mutations.length);
    } catch (err: unknown) {
      this.handleError(toError(err));
    }
  }

  private loadOrCreateInstanceId(): string {
    const dataPath = this.config.instanceDataPath
      ? resolve(this.config.instanceDataPath)
      : resolve(this.guardrailsConfig.workspaceRoot, ".safefence", "instance.json");

    try {
      if (existsSync(dataPath)) {
        const data = JSON.parse(readFileSync(dataPath, "utf-8")) as InstanceIdentity;
        if (data.instanceId) return data.instanceId;
      }
    } catch {
      // Corrupt file, regenerate
    }

    const instanceId = randomUUID();
    const identity: InstanceIdentity = { instanceId, registeredAt: Date.now() };
    mkdirSync(dirname(dataPath), { recursive: true });
    writeFileSync(dataPath, JSON.stringify(identity, null, 2), "utf-8");
    return instanceId;
  }

  private handleError(err: Error): void {
    this.onError?.(err);
  }

  private setStatus(status: AgentStatus): void {
    if (this._status !== status) {
      this._status = status;
      this.onStatusChange?.(status);
    }
  }
}
