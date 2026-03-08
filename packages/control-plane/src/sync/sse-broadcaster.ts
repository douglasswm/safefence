/**
 * SSE broadcaster: publishes sync events via Redis pub/sub,
 * and streams them to connected instances via SSE.
 */

import type { Context } from "hono";
import { streamSSE } from "hono/streaming";
import type Redis from "ioredis";

export interface SyncEventMessage {
  type: "policy_changed" | "rbac_changed" | "force_resync" | "revoked";
  key?: string;
  version?: number;
}

export class SseBroadcaster {
  private redis: Redis;
  private subRedis: Redis;
  private listeners: Map<string, Set<(event: SyncEventMessage) => void>> = new Map();

  constructor(redis: Redis, subRedis: Redis) {
    this.redis = redis;
    this.subRedis = subRedis;

    this.subRedis.on("message", (channel: string, message: string) => {
      const orgId = channel.replace("safefence:sync:", "");
      const listeners = this.listeners.get(orgId);
      if (!listeners) return;
      try {
        const event = JSON.parse(message) as SyncEventMessage;
        for (const listener of listeners) {
          listener(event);
        }
      } catch {
        // Ignore malformed messages
      }
    });
  }

  /** Publish a sync event to all instances in an org. */
  async publish(orgId: string, event: SyncEventMessage): Promise<void> {
    await this.redis.publish(`safefence:sync:${orgId}`, JSON.stringify(event));
  }

  /** Subscribe an instance to org events. Returns unsubscribe function. */
  subscribe(orgId: string, listener: (event: SyncEventMessage) => void): () => void {
    if (!this.listeners.has(orgId)) {
      this.listeners.set(orgId, new Set());
      this.subRedis.subscribe(`safefence:sync:${orgId}`).catch(() => {});
    }
    this.listeners.get(orgId)!.add(listener);

    return () => {
      const set = this.listeners.get(orgId);
      if (set) {
        set.delete(listener);
        if (set.size === 0) {
          this.listeners.delete(orgId);
          this.subRedis.unsubscribe(`safefence:sync:${orgId}`).catch(() => {});
        }
      }
    };
  }

  /** Hono SSE stream handler for instance connections. */
  handleSseStream(c: Context, orgId: string): Response {
    return streamSSE(c, async (stream) => {
      const unsubscribe = this.subscribe(orgId, (event) => {
        stream.writeSSE({ data: JSON.stringify(event) }).catch(() => {});
      });

      const keepAlive = setInterval(() => {
        stream.writeSSE({ event: "ping", data: "" }).catch(() => {});
      }, 15_000);

      // Resolve when client disconnects (avoids leaked promise)
      await new Promise<void>((resolve) => {
        stream.onAbort(() => {
          clearInterval(keepAlive);
          unsubscribe();
          resolve();
        });
      });
    });
  }
}
