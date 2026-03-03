import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("supply chain policy", () => {
  it("denies untrusted skill source", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "skills.install",
      args: {
        source: "https://evil.example.com/skill",
        hash: "sha256:abc"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.SUPPLY_CHAIN_UNTRUSTED_SOURCE);
  });

  it("denies remote source without hash", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "skills.install",
      args: {
        source: "https://github.com/openclaw/safe-skill"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.SUPPLY_CHAIN_HASH_REQUIRED);
  });
});
