import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("budget controls", () => {
  it("denies when request budget is exceeded", async () => {
    const config = createDefaultConfig("/workspace/project");
    config.limits.maxRequestsPerMinute = 1;

    const engine = new GuardrailsEngine(config);

    const first = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "hello"
    });

    const second = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "hello again"
    });

    expect(first.decision).not.toBe("DENY");
    expect(second.decision).toBe("DENY");
    expect(second.reasonCodes).toContain(REASON_CODES.BUDGET_REQUEST_EXCEEDED);
  });

  it("partitions request budget by sender and conversation in tenancy mode", async () => {
    const config = createDefaultConfig("/workspace/project");
    config.limits.maxRequestsPerMinute = 1;
    config.tenancy.budgetKeyMode = "agent+principal+conversation";
    const engine = new GuardrailsEngine(config);

    const firstSenderFirst = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "from member-1",
      metadata: {
        principal: {
          senderId: "member-1",
          role: "member",
          channelType: "group",
          conversationId: "conv-1",
          mentionedAgent: true
        }
      }
    });

    const firstSenderSecond = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "from member-1 again",
      metadata: {
        principal: {
          senderId: "member-1",
          role: "member",
          channelType: "group",
          conversationId: "conv-1",
          mentionedAgent: true
        }
      }
    });

    const secondSenderFirst = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "from member-2",
      metadata: {
        principal: {
          senderId: "member-2",
          role: "member",
          channelType: "group",
          conversationId: "conv-1",
          mentionedAgent: true
        }
      }
    });

    expect(firstSenderFirst.decision).not.toBe("DENY");
    expect(firstSenderSecond.decision).toBe("DENY");
    expect(firstSenderSecond.reasonCodes).toContain(REASON_CODES.BUDGET_REQUEST_EXCEEDED);
    expect(secondSenderFirst.decision).not.toBe("DENY");
  });
});
