import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import type { CustomValidator } from "../src/core/custom-validator.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

const workspaceRoot = "/workspace/project";

describe("Custom Validators", () => {
  it("invokes sync custom validator and aggregates hits", async () => {
    const validator: CustomValidator = {
      id: "spending-limit",
      phases: ["before_tool_call"],
      validate() {
        return [
          {
            ruleId: "spending-limit",
            reasonCode: "SPENDING_LIMIT_EXCEEDED",
            decision: "DENY",
            weight: 0.9
          }
        ];
      }
    };

    const engine = new GuardrailsEngine(createDefaultConfig(workspaceRoot), {
      customValidators: [validator]
    });

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "read",
      content: "safe content"
    });

    expect(decision.reasonCodes).toContain("SPENDING_LIMIT_EXCEEDED");
  });

  it("invokes async custom validator", async () => {
    const validator: CustomValidator = {
      id: "async-check",
      phases: ["message_received"],
      async validate() {
        return [
          {
            ruleId: "async-check",
            reasonCode: "CUSTOM_ASYNC_FAIL",
            decision: "DENY",
            weight: 0.5
          }
        ];
      }
    };

    const engine = new GuardrailsEngine(createDefaultConfig(workspaceRoot), {
      customValidators: [validator]
    });

    const decision = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "hello"
    });

    expect(decision.reasonCodes).toContain("CUSTOM_ASYNC_FAIL");
  });

  it("filters validators by phase", async () => {
    const validator: CustomValidator = {
      id: "tool-only",
      phases: ["before_tool_call"],
      validate() {
        return [
          {
            ruleId: "tool-only",
            reasonCode: "TOOL_CUSTOM_DENY",
            decision: "DENY",
            weight: 0.5
          }
        ];
      }
    };

    const engine = new GuardrailsEngine(createDefaultConfig(workspaceRoot), {
      customValidators: [validator]
    });

    // Should NOT fire on message_received
    const decision = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "hello"
    });

    expect(decision.reasonCodes).not.toContain("TOOL_CUSTOM_DENY");
  });

  it("runs validator with empty phases array on all phases", async () => {
    const validator: CustomValidator = {
      id: "all-phases",
      phases: [],
      validate() {
        return [
          {
            ruleId: "all-phases",
            reasonCode: "ALWAYS_FIRES",
            decision: "DENY",
            weight: 0.3
          }
        ];
      }
    };

    const engine = new GuardrailsEngine(createDefaultConfig(workspaceRoot), {
      customValidators: [validator]
    });

    const decision = await engine.evaluate({
      phase: "message_sending",
      agentId: "agent-1",
      content: "safe message"
    });

    expect(decision.reasonCodes).toContain("ALWAYS_FIRES");
  });

  it("swallows errors from custom validators without breaking pipeline", async () => {
    const badValidator: CustomValidator = {
      id: "throws",
      phases: [],
      validate() {
        throw new Error("validator crashed");
      }
    };

    const engine = new GuardrailsEngine(createDefaultConfig(workspaceRoot), {
      customValidators: [badValidator]
    });

    const decision = await engine.evaluate({
      phase: "message_received",
      agentId: "agent-1",
      content: "hello"
    });

    // Should still get a valid decision
    expect(decision.decision).toBeDefined();
  });
});
