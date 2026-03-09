/**
 * StreamingAuditSink: Wraps a local AuditSink, buffers events in memory,
 * and flushes them to the control plane in batches via REST.
 */

import { createHmac } from "node:crypto";
import type { AuditEvent, AuditSink } from "../core/audit-sink.js";
import { toError } from "../utils/args.js";
import type { ControlPlaneHttpClient } from "./http-client.js";
import type { AuditUploadEvent } from "./types.js";

export interface StreamingAuditSinkOptions {
  /** Underlying local audit sink (writes continue locally) */
  inner: AuditSink;
  /** HTTP client for batch uploads */
  httpClient: ControlPlaneHttpClient;
  /** Instance ID for the batch request */
  instanceId: string;
  /** Flush interval in ms (default: 5000) */
  flushIntervalMs?: number;
  /** Max events per batch (default: 500) */
  batchSize?: number;
  /** Max buffer size before dropping oldest (default: 10000) */
  maxBufferSize?: number;
  /** Error callback */
  onError?: (error: Error) => void;
}

export class StreamingAuditSink implements AuditSink {
  private readonly inner: AuditSink;
  private readonly httpClient: ControlPlaneHttpClient;
  private readonly instanceId: string;
  private readonly flushIntervalMs: number;
  private readonly batchSize: number;
  private readonly maxBufferSize: number;
  private readonly onError?: (error: Error) => void;
  private readonly buffer: AuditUploadEvent[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private seq = 0;
  private ackedCursor = 0;
  private flushing = false;
  private prevHash = "0";

  constructor(opts: StreamingAuditSinkOptions) {
    this.inner = opts.inner;
    this.httpClient = opts.httpClient;
    this.instanceId = opts.instanceId;
    this.flushIntervalMs = opts.flushIntervalMs ?? 5000;
    this.batchSize = opts.batchSize ?? 500;
    this.maxBufferSize = opts.maxBufferSize ?? 10_000;
    this.onError = opts.onError;
  }

  get auditCursor(): number {
    return this.ackedCursor;
  }

  get pendingCount(): number {
    return this.buffer.length;
  }

  /** Start the periodic flush timer. */
  start(): void {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      this.flush().catch((err) => {
        this.onError?.(toError(err));
      });
    }, this.flushIntervalMs);
  }

  /** Stop the periodic flush timer. */
  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  append(event: AuditEvent): void {
    // Always write locally first
    this.inner.append(event);

    // Buffer for upstream sync
    this.seq += 1;

    // H7: Compute hash chain
    const eventContent = JSON.stringify({
      seq: this.seq,
      botInstanceId: event.botInstanceId,
      eventType: `${event.phase}.${event.decision}`,
      decision: event.decision,
    });
    const eventHash = createHmac("sha256", this.instanceId)
      .update(this.prevHash + eventContent)
      .digest("hex");

    const uploadEvent: AuditUploadEvent = {
      id: `${this.instanceId}-${this.seq}`,
      seq: this.seq,
      timestamp: Date.now(),
      botInstanceId: event.botInstanceId,
      eventType: `${event.phase}.${event.decision}`,
      decision: event.decision === "ALLOW" ? "allow" : event.decision === "DENY" ? "deny" : undefined,
      details: {
        reasonCodes: event.reasonCodes,
        riskScore: event.riskScore,
        elapsedMs: event.elapsedMs,
        agentId: event.agentId,
        toolName: event.toolName,
        senderId: event.senderId,
        approvalRequestId: event.approvalRequestId,
      },
      prevHash: this.prevHash,
      eventHash,
    };
    this.prevHash = eventHash;

    if (this.buffer.length >= this.maxBufferSize) {
      console.warn("[safefence] Buffer full, dropping oldest event");
      this.buffer.shift(); // Drop oldest
    }
    this.buffer.push(uploadEvent);
  }

  /** Flush buffered events to control plane. */
  async flush(): Promise<void> {
    if (this.flushing || this.buffer.length === 0) return;
    this.flushing = true;

    try {
      const batch = this.buffer.slice(0, this.batchSize);
      const lastSeq = batch[batch.length - 1].seq;

      const response = await this.httpClient.pushAuditBatch({
        instanceId: this.instanceId,
        events: batch,
        cursor: lastSeq,
      });

      // Remove acked events from buffer — batch is sorted by seq, so find the cutoff
      const ackedIdx = batch.findIndex((e) => e.seq > response.ackedCursor);
      const removeCount = ackedIdx === -1 ? batch.length : ackedIdx;
      this.buffer.splice(0, removeCount);
      this.ackedCursor = response.ackedCursor;
    } catch (err: unknown) {
      this.onError?.(toError(err));
      // Events remain in buffer for retry
    } finally {
      this.flushing = false;
    }
  }
}
