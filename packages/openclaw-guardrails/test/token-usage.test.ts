import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { TokenUsageStore } from "../src/core/token-usage-store.js";
import type { TokenUsageRecord } from "../src/core/token-usage-store.js";

function makeRecord(overrides: Partial<TokenUsageRecord> = {}): TokenUsageRecord {
  return {
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    senderId: "user-1",
    conversationId: "conv-1",
    inputTokens: 100,
    outputTokens: 50,
    totalTokens: 150,
    ...overrides
  };
}

describe("TokenUsageStore", () => {
  const tmpFiles: string[] = [];

  afterEach(() => {
    for (const f of tmpFiles) {
      try { fs.unlinkSync(f); } catch { /* ignore */ }
    }
    tmpFiles.length = 0;
  });

  function tmpPath(): string {
    const p = path.join(os.tmpdir(), `token-usage-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    tmpFiles.push(p);
    return p;
  }

  it("records and retrieves usage by user", () => {
    const store = new TokenUsageStore();
    store.record(makeRecord({ senderId: "user-1" }));
    store.record(makeRecord({ senderId: "user-2" }));
    store.record(makeRecord({ senderId: "user-1" }));

    const user1 = store.getByUser("user-1");
    expect(user1).toHaveLength(2);

    const user2 = store.getByUser("user-2");
    expect(user2).toHaveLength(1);
  });

  it("computes correct summary", () => {
    const store = new TokenUsageStore();
    store.record(makeRecord({ senderId: "user-1", inputTokens: 100, outputTokens: 50, totalTokens: 150 }));
    store.record(makeRecord({ senderId: "user-2", inputTokens: 200, outputTokens: 100, totalTokens: 300 }));

    const summary = store.getSummary();
    expect(summary.totalInputTokens).toBe(300);
    expect(summary.totalOutputTokens).toBe(150);
    expect(summary.totalTokens).toBe(450);
    expect(summary.recordCount).toBe(2);
    expect(summary.byUser["user-1"].total).toBe(150);
    expect(summary.byUser["user-2"].total).toBe(300);
  });

  it("persists to JSONL and loads on restart", () => {
    const filePath = tmpPath();

    // Write session
    const store1 = new TokenUsageStore(filePath);
    store1.record(makeRecord({ senderId: "user-1", totalTokens: 100 }));
    store1.record(makeRecord({ senderId: "user-2", totalTokens: 200 }));
    store1.close();

    // Read session
    const store2 = new TokenUsageStore(filePath);
    const summary = store2.getSummary();
    expect(summary.recordCount).toBe(2);
    expect(summary.totalTokens).toBe(300);
    store2.close();
  });

  it("handles empty storage path (in-memory only)", () => {
    const store = new TokenUsageStore();
    store.record(makeRecord());
    expect(store.getSummary().recordCount).toBe(1);
  });
});
