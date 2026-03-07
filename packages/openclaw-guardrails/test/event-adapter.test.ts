import { describe, expect, it } from "vitest";
import {
  mapBeforeAgentStart,
  mapMessageReceived,
  mapBeforeToolCall,
  mapToolResultPersist,
  mapMessageSending,
  mapAgentEnd,
  mapToBeforeAgentStartResult,
  mapToBeforeToolCallResult,
  mapToMessageSendingResult,
  mapToToolResultPersistResult,
} from "../src/plugin/event-adapter.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import type { OpenClawHookResult } from "../src/plugin/openclaw-adapter.js";

describe("event-adapter: event → OpenClawContext mappers", () => {
  it("mapBeforeAgentStart maps prompt and agent context", () => {
    const ctx = mapBeforeAgentStart(
      { prompt: "Hello world" },
      { agentId: "a1", sessionKey: "s1", channelId: "telegram" }
    );
    expect(ctx.agentId).toBe("a1");
    expect(ctx.prompt).toBe("Hello world");
    expect(ctx.channelId).toBe("telegram");
    expect(ctx.conversationId).toBe("s1");
  });

  it("mapMessageReceived maps sender, content, and channel", () => {
    const ctx = mapMessageReceived(
      { from: "user-1", content: "test message", metadata: { key: "val" } },
      { channelId: "discord", conversationId: "conv-1" }
    );
    expect(ctx.senderId).toBe("user-1");
    expect(ctx.content).toBe("test message");
    expect(ctx.channelId).toBe("discord");
    expect(ctx.conversationId).toBe("conv-1");
    expect(ctx.metadata).toEqual({ key: "val" });
  });

  it("mapBeforeToolCall maps tool name, params, and agent context", () => {
    const ctx = mapBeforeToolCall(
      { toolName: "exec", params: { cmd: "ls" }, runId: "r1" },
      { agentId: "a1", sessionKey: "s1", toolName: "exec" }
    );
    expect(ctx.agentId).toBe("a1");
    expect(ctx.toolName).toBe("exec");
    expect(ctx.args).toEqual({ cmd: "ls" });
    expect(ctx.conversationId).toBe("s1");
  });

  it("mapToolResultPersist extracts content from message", () => {
    const ctx = mapToolResultPersist(
      { toolName: "read", message: { role: "tool", content: "file contents" } },
      { agentId: "a1", sessionKey: "s1", toolName: "read" }
    );
    expect(ctx.agentId).toBe("a1");
    expect(ctx.toolName).toBe("read");
    expect(ctx.output).toBe("file contents");
  });

  it("mapToolResultPersist handles non-string content gracefully", () => {
    const ctx = mapToolResultPersist(
      { message: { role: "tool", content: { nested: true } } },
      { agentId: "a1", sessionKey: "s1" }
    );
    expect(ctx.output).toBeUndefined();
  });

  it("mapMessageSending maps content and channel", () => {
    const ctx = mapMessageSending(
      { to: "user-1", content: "Hello!", metadata: { key: "val" } },
      { channelId: "telegram", conversationId: "conv-1" }
    );
    expect(ctx.content).toBe("Hello!");
    expect(ctx.channelId).toBe("telegram");
    expect(ctx.conversationId).toBe("conv-1");
  });

  it("mapAgentEnd maps success, error, and duration into metadata", () => {
    const ctx = mapAgentEnd(
      { messages: [], success: true, durationMs: 1234 },
      { agentId: "a1", sessionKey: "s1" }
    );
    expect(ctx.agentId).toBe("a1");
    expect(ctx.metadata?.success).toBe(true);
    expect(ctx.metadata?.durationMs).toBe(1234);
  });
});

describe("event-adapter: result mappers", () => {
  it("mapToBeforeAgentStartResult extracts systemPrompt as prependSystemContext", () => {
    const hookResult: OpenClawHookResult = {
      systemPrompt: "Security policy (immutable): ..."
    };
    const result = mapToBeforeAgentStartResult(hookResult);
    expect(result.prependSystemContext).toBe("Security policy (immutable): ...");
  });

  it("mapToBeforeAgentStartResult returns empty when no systemPrompt", () => {
    const result = mapToBeforeAgentStartResult({});
    expect(result.prependSystemContext).toBeUndefined();
  });

  it("mapToBeforeToolCallResult maps blocked to block=true with reason", () => {
    const hookResult: OpenClawHookResult = {
      blocked: true,
      reasonCodes: [REASON_CODES.TOOL_NOT_ALLOWED, REASON_CODES.BUDGET_REQUEST_EXCEEDED]
    };
    const result = mapToBeforeToolCallResult(hookResult);
    expect(result.block).toBe(true);
    expect(result.blockReason).toContain(REASON_CODES.TOOL_NOT_ALLOWED);
    expect(result.blockReason).toContain(REASON_CODES.BUDGET_REQUEST_EXCEEDED);
  });

  it("mapToBeforeToolCallResult returns empty for allowed actions", () => {
    const result = mapToBeforeToolCallResult({});
    expect(result.block).toBeUndefined();
  });

  it("mapToMessageSendingResult returns cancel=true for blocked messages", () => {
    const hookResult: OpenClawHookResult = { blocked: true, cancel: true };
    const result = mapToMessageSendingResult(hookResult);
    expect(result.cancel).toBe(true);
  });

  it("mapToMessageSendingResult returns redacted content when available", () => {
    const hookResult: OpenClawHookResult = {
      guardrails: {
        decision: {
          decision: "REDACT",
          reasonCodes: ["PII"],
          riskScore: 0.8,
          redactedContent: "email=[REDACTED]",
          telemetry: { matchedRules: ["pii"], elapsedMs: 1 }
        }
      }
    };
    const result = mapToMessageSendingResult(hookResult);
    expect(result.content).toBe("email=[REDACTED]");
    expect(result.cancel).toBeUndefined();
  });

  it("mapToMessageSendingResult returns empty for allowed messages", () => {
    const result = mapToMessageSendingResult({});
    expect(result.cancel).toBeUndefined();
    expect(result.content).toBeUndefined();
  });

  it("mapToToolResultPersistResult returns modified message with redacted content", () => {
    const hookResult: OpenClawHookResult = {
      guardrails: {
        decision: {
          decision: "REDACT",
          reasonCodes: ["SECRET"],
          riskScore: 0.9,
          redactedContent: "token=[REDACTED]",
          telemetry: { matchedRules: ["secret"], elapsedMs: 1 }
        }
      }
    };
    const originalEvent = { message: { role: "tool", content: "token=abc123" } };
    const result = mapToToolResultPersistResult(hookResult, originalEvent);
    expect(result.message?.content).toBe("token=[REDACTED]");
    expect(result.message?.role).toBe("tool");
  });

  it("mapToToolResultPersistResult returns blocked message for denied results", () => {
    const hookResult: OpenClawHookResult = { blocked: true };
    const originalEvent = { message: { role: "tool", content: "secret data" } };
    const result = mapToToolResultPersistResult(hookResult, originalEvent);
    expect(result.message?.content).toBe("[guardrails] content blocked");
  });

  it("mapToToolResultPersistResult returns empty for allowed results", () => {
    const result = mapToToolResultPersistResult({}, { message: { role: "tool", content: "ok" } });
    expect(result.message).toBeUndefined();
  });
});
