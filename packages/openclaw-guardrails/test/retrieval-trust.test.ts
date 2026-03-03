import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("retrieval trust", () => {
  it("denies high-risk tool call when retrieval trust metadata is missing", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: { cmd: "ls" },
      metadata: {
        sourceType: "retrieval"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.RETRIEVAL_TRUST_REQUIRED);
  });

  it("denies when retrieval trust level is below configured threshold", async () => {
    const config = createDefaultConfig("/workspace/project");
    config.retrievalTrust = {
      requiredForToolExecution: true,
      minimumTrustLevel: "high",
      requireSignedSource: false
    };

    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: { cmd: "ls" },
      metadata: {
        sourceType: "retrieval",
        trustLevel: "medium"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.RETRIEVAL_TRUST_LEVEL_TOO_LOW);
  });
});
