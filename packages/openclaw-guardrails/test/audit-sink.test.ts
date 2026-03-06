import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonlAuditSink, NoopAuditSink } from "../src/core/audit-sink.js";
import type { AuditEvent } from "../src/core/audit-sink.js";

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    phase: "before_tool_call",
    agentId: "agent-1",
    decision: "ALLOW",
    reasonCodes: [],
    riskScore: 0,
    elapsedMs: 5,
    ...overrides
  };
}

describe("JsonlAuditSink", () => {
  const tmpFiles: string[] = [];

  afterEach(() => {
    for (const f of tmpFiles) {
      try { fs.unlinkSync(f); } catch { /* ignore */ }
    }
    tmpFiles.length = 0;
  });

  function tmpPath(): string {
    const p = path.join(os.tmpdir(), `audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    tmpFiles.push(p);
    return p;
  }

  it("writes JSONL lines with newline delimiter", () => {
    const filePath = tmpPath();
    const sink = new JsonlAuditSink(filePath);

    sink.append(makeEvent({ decision: "ALLOW" }));
    sink.append(makeEvent({ decision: "DENY", reasonCodes: ["PROMPT_INJECTION"] }));
    sink.close();

    const lines = fs.readFileSync(filePath, "utf-8").split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);

    const first = JSON.parse(lines[0]);
    expect(first.decision).toBe("ALLOW");

    const second = JSON.parse(lines[1]);
    expect(second.decision).toBe("DENY");
    expect(second.reasonCodes).toContain("PROMPT_INJECTION");
  });

  it("creates directories if they don't exist", () => {
    const dir = path.join(os.tmpdir(), `audit-nested-${Date.now()}`);
    const filePath = path.join(dir, "audit.jsonl");
    tmpFiles.push(filePath);

    const sink = new JsonlAuditSink(filePath);
    sink.append(makeEvent());
    sink.close();

    expect(fs.existsSync(filePath)).toBe(true);
    fs.rmSync(dir, { recursive: true });
  });

  it("includes all event fields in output", () => {
    const filePath = tmpPath();
    const sink = new JsonlAuditSink(filePath);

    sink.append(makeEvent({
      phase: "message_sending",
      agentId: "agent-42",
      senderId: "user-1",
      toolName: "exec",
      decision: "DENY",
      reasonCodes: ["COMMAND_BINARY_NOT_ALLOWED"],
      riskScore: 0.8,
      elapsedMs: 12,
      approvalRequestId: "req-123"
    }));
    sink.close();

    const lines = fs.readFileSync(filePath, "utf-8").split("\n").filter(Boolean);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.phase).toBe("message_sending");
    expect(parsed.agentId).toBe("agent-42");
    expect(parsed.senderId).toBe("user-1");
    expect(parsed.toolName).toBe("exec");
    expect(parsed.approvalRequestId).toBe("req-123");
  });
});

describe("NoopAuditSink", () => {
  it("does not throw on append", () => {
    const sink = new NoopAuditSink();
    expect(() => sink.append(makeEvent())).not.toThrow();
  });
});
