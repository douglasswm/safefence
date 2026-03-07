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
  private totalInput = 0;
  private totalOutput = 0;
  private totalTokens = 0;
  private byUser: Record<string, { input: number; output: number; total: number }> = {};

  constructor(storagePath?: string) {
    if (storagePath) {
      this.records = readJsonlFile<TokenUsageRecord>(storagePath);
      this.writer = new JsonlWriter(storagePath);
      for (const r of this.records) {
        this.addToCounters(r);
      }
    }
  }

  private addToCounters(r: TokenUsageRecord): void {
    this.totalInput += r.inputTokens;
    this.totalOutput += r.outputTokens;
    this.totalTokens += r.totalTokens;

    if (!this.byUser[r.senderId]) {
      this.byUser[r.senderId] = { input: 0, output: 0, total: 0 };
    }
    this.byUser[r.senderId].input += r.inputTokens;
    this.byUser[r.senderId].output += r.outputTokens;
    this.byUser[r.senderId].total += r.totalTokens;
  }

  record(entry: TokenUsageRecord): void {
    this.records.push(entry);
    this.addToCounters(entry);
    this.writer?.append(entry);
  }

  getByUser(senderId: string): TokenUsageRecord[] {
    return this.records.filter((r) => r.senderId === senderId);
  }

  getSummary(): TokenUsageSummary {
    return {
      totalInputTokens: this.totalInput,
      totalOutputTokens: this.totalOutput,
      totalTokens: this.totalTokens,
      recordCount: this.records.length,
      byUser: { ...this.byUser }
    };
  }

  close(): void {
    this.writer?.close();
    this.writer = null;
  }
}
