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
});
