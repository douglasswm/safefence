import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

describe("regression: openclaw advisory classes", () => {
  it("blocks gatewayUrl override abuse class (CVE-2026-26322)", async () => {
    const engine = new GuardrailsEngine(createDefaultConfig("/workspace/project"));

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: {
        gatewayUrl: "http://8.8.8.8/relay"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.NETWORK_HOST_BLOCKED);
  });

  it("blocks targetDir path escape class (CVE-2026-27008)", async () => {
    const engine = new GuardrailsEngine(createDefaultConfig("/workspace/project"));

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "skills.install",
      args: {
        source: "https://github.com/openclaw/safe-skill",
        targetDir: "../../../../tmp/owned",
        hash: "sha256:trusted"
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.PATH_TRAVERSAL);
  });

  it("blocks symlink workspace escape class (GHSA-fgvx-58p6-gjwc)", async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-regression-"));
    const workspace = path.join(tempRoot, "workspace");
    const outside = path.join(tempRoot, "outside");
    const symlinkPath = path.join(workspace, "link-out");

    await fs.mkdir(workspace, { recursive: true });
    await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, "secret.txt"), "secret", "utf8");
    await fs.symlink(path.join(outside, "secret.txt"), symlinkPath);

    const config = createDefaultConfig(workspace);
    const engine = new GuardrailsEngine(config);

    const decision = await engine.evaluate({
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "read",
      args: {
        path: symlinkPath
      }
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.reasonCodes).toContain(REASON_CODES.PATH_SYMLINK_TRAVERSAL);
  });
});
