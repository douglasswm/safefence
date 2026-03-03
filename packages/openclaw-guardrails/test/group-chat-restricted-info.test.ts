import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("group chat restricted info handling", () => {
  it("redacts restricted output for non-owner group principals", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "tool_result_persist",
      agentId: "agent-1",
      content: "customer secret payload",
      metadata: {
        dataClass: "secret",
        principal: {
          senderId: "member-1",
          role: "member",
          channelType: "group",
          conversationId: "conv-1",
          mentionedAgent: true
        }
      }
    });

    expect(decision.decision).toBe("REDACT");
    expect(decision.reasonCodes).toContain(REASON_CODES.RESTRICTED_INFO_ROLE_BLOCKED);
    expect(decision.redactedContent).toContain("[REDACTED:SECRET]");
  });

  it("allows owner requests in DM without requiring approval", async () => {
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
          channelType: "dm",
          conversationId: "dm-1",
          mentionedAgent: true
        },
        dataClass: "restricted"
      }
    });

    expect(decision.decision).toBe("ALLOW");
    expect(decision.reasonCodes).not.toContain(REASON_CODES.OWNER_APPROVAL_REQUIRED);
  });
});
