import { JsonlWriter, readJsonlFile } from "./jsonl-writer.js";
import type { TokenUsageSummary } from "./types.js";

export interface TokenUsageRecord {
  timestamp: string;
  agentId: string;
  senderId: string;
  conversationId: string;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  toolName?: string;
}

export class TokenUsageStore {
  private records: TokenUsageRecord[] = [];
  private writer: JsonlWriter | null = null;

  constructor(storagePath?: string) {
    if (storagePath) {
      this.records = readJsonlFile<TokenUsageRecord>(storagePath);
      this.writer = new JsonlWriter(storagePath);
    }
  }

  record(entry: TokenUsageRecord): void {
    this.records.push(entry);
    this.writer?.append(entry);
  }

  getByUser(senderId: string): TokenUsageRecord[] {
    return this.records.filter((r) => r.senderId === senderId);
  }

  getSummary(): TokenUsageSummary {
    const byUser: Record<string, { input: number; output: number; total: number }> = {};
    let totalInput = 0;
    let totalOutput = 0;
    let totalTokens = 0;

    for (const r of this.records) {
      totalInput += r.inputTokens;
      totalOutput += r.outputTokens;
      totalTokens += r.totalTokens;

      if (!byUser[r.senderId]) {
        byUser[r.senderId] = { input: 0, output: 0, total: 0 };
      }
      byUser[r.senderId].input += r.inputTokens;
      byUser[r.senderId].output += r.outputTokens;
      byUser[r.senderId].total += r.totalTokens;
    }

    return {
      totalInputTokens: totalInput,
      totalOutputTokens: totalOutput,
      totalTokens,
      recordCount: this.records.length,
      byUser
    };
  }

  close(): void {
    this.writer?.close();
    this.writer = null;
  }
}
