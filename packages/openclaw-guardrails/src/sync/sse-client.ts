/**
 * SSE client for SafeFence control plane event stream.
 * Auto-reconnects on disconnect with exponential backoff.
 */

import type { SyncEvent } from "./types.js";

export interface SseClientOptions {
  url: string;
  token: string;
  onEvent: (event: SyncEvent) => void;
  onError?: (error: Error) => void;
  onConnect?: () => void;
  /** Initial reconnect delay in ms (default: 1000) */
  reconnectDelayMs?: number;
  /** Max reconnect delay in ms (default: 30000) */
  maxReconnectDelayMs?: number;
}

export class SseClient {
  private url: string;
  private token: string;
  private onEvent: (event: SyncEvent) => void;
  private onError?: (error: Error) => void;
  private onConnect?: () => void;
  private reconnectDelayMs: number;
  private maxReconnectDelayMs: number;
  private currentDelay: number;
  private abortController: AbortController | null = null;
  private running = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(opts: SseClientOptions) {
    this.url = opts.url;
    this.token = opts.token;
    this.onEvent = opts.onEvent;
    this.onError = opts.onError;
    this.onConnect = opts.onConnect;
    this.reconnectDelayMs = opts.reconnectDelayMs ?? 1000;
    this.maxReconnectDelayMs = opts.maxReconnectDelayMs ?? 30_000;
    this.currentDelay = this.reconnectDelayMs;
  }

  updateToken(token: string): void {
    this.token = token;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.connect();
  }

  stop(): void {
    this.running = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  private async connect(): Promise<void> {
    if (!this.running) return;

    this.abortController = new AbortController();
    try {
      const res = await fetch(this.url, {
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: "text/event-stream",
          "Cache-Control": "no-cache",
        },
        signal: this.abortController.signal,
      });

      if (!res.ok || !res.body) {
        throw new Error(`SSE connect failed: ${res.status} ${res.statusText}`);
      }

      // Reset backoff on successful connection
      this.currentDelay = this.reconnectDelayMs;
      this.onConnect?.();

      await this.readStream(res.body);
    } catch (err: unknown) {
      if (!this.running) return; // intentional stop
      const error = err instanceof Error ? err : new Error(String(err));
      if (error.name !== "AbortError") {
        this.onError?.(error);
      }
    }

    // Reconnect with backoff
    if (this.running) {
      this.reconnectTimer = setTimeout(() => {
        this.currentDelay = Math.min(this.currentDelay * 2, this.maxReconnectDelayMs);
        this.connect();
      }, this.currentDelay);
    }
  }

  private async readStream(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (this.running) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const events = this.parseEvents(buffer);
        buffer = events.remaining;

        for (const event of events.parsed) {
          this.onEvent(event);
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  private parseEvents(buffer: string): { parsed: SyncEvent[]; remaining: string } {
    const parsed: SyncEvent[] = [];
    const blocks = buffer.split("\n\n");
    const remaining = blocks.pop() ?? ""; // last incomplete block

    for (const block of blocks) {
      if (!block.trim()) continue;
      let data = "";
      for (const line of block.split("\n")) {
        if (line.startsWith("data: ")) {
          data += line.slice(6);
        }
      }
      if (data) {
        try {
          const event = JSON.parse(data);
          // L1: Validate SSE event structure
          if (typeof event.type === "string") {
            parsed.push(event as SyncEvent);
          }
        } catch {
          // Skip malformed events
        }
      }
    }

    return { parsed, remaining };
  }
}
