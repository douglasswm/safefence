import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("principal authorization", () => {
  it("requires owner approval for member restricted tool usage in groups", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: { cmd: "ls" },
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

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.OWNER_APPROVAL_REQUIRED);
    expect(decision.approvalChallenge).toBeDefined();
  });

  it("allows owner restricted tool usage when command policy is satisfied", async () => {
    const config = createDefaultConfig("/workspace/project");
    config.principal.ownerIds = ["owner-1"];
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: { cmd: "ls" },
      metadata: {
        principal: {
          senderId: "owner-1",
          role: "owner",
          channelType: "group",
          conversationId: "conv-1",
          mentionedAgent: true
        }
      }
    });

    expect(decision.decision).toBe("ALLOW");
  });
});
