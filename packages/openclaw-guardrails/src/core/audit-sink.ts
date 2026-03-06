import { JsonlWriter } from "./jsonl-writer.js";
import type { Decision, Phase } from "./types.js";

export interface AuditEvent {
  timestamp: string;
  phase: Phase;
  agentId: string;
  senderId?: string;
  toolName?: string;
  decision: Decision;
  reasonCodes: string[];
  riskScore: number;
  elapsedMs: number;
  approvalRequestId?: string;
}

export interface AuditSink {
  append(event: AuditEvent): void;
}

export class JsonlAuditSink implements AuditSink {
  private readonly writer: JsonlWriter;

  constructor(filePath: string) {
    this.writer = new JsonlWriter(filePath);
  }

  append(event: AuditEvent): void {
    this.writer.append(event);
  }

  close(): void {
    this.writer.close();
  }
}

export class NoopAuditSink implements AuditSink {
  append(_event: AuditEvent): void {
    // intentionally empty
  }
}
