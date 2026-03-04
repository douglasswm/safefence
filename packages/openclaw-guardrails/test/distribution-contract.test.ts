import fs from "node:fs";
import { describe, expect, it } from "vitest";
import registerOpenClawGuardrails from "../src/plugin/openclaw-extension.js";

interface HookRegistration {
  name?: string;
  description?: string;
}

interface RegisteredHook {
  hookName: string;
  handler: (context: unknown) => Promise<unknown> | unknown;
  registration?: HookRegistration;
}

function readJson(relativePath: string): unknown {
  const url = new URL(relativePath, import.meta.url);
  const content = fs.readFileSync(url, "utf8");
  return JSON.parse(content);
}

describe("distribution contract", () => {
  it("declares OpenClaw npm extension entry in package.json", () => {
    const packageJson = readJson("../package.json") as {
      openclaw?: { extensions?: unknown };
    };

    expect(Array.isArray(packageJson.openclaw?.extensions)).toBe(true);
    expect(packageJson.openclaw?.extensions).toContain(
      "./dist/plugin/openclaw-extension.js"
    );
  });

  it("declares required manifest id and schema", () => {
    const manifest = readJson("../openclaw.plugin.json") as {
      id?: unknown;
      entry?: unknown;
      configSchema?: unknown;
    };

    expect(manifest.id).toBe("openclaw-guardrails");
    expect(manifest.entry).toBe("dist/plugin/openclaw-extension.js");
    expect(manifest.configSchema).toBeDefined();
    expect(typeof manifest.configSchema).toBe("object");
  });

  it("exports a default register contract and registers expected hooks", async () => {
    const registered: RegisteredHook[] = [];

    registerOpenClawGuardrails({
      config: {
        plugins: {
          entries: {
            "openclaw-guardrails": {
              config: {
                workspaceRoot: "/workspace/project"
              }
            }
          }
        }
      },
      registerHook: (
        hookName: string,
        handler: (context: unknown) => Promise<unknown> | unknown,
        registration?: HookRegistration
      ) => {
        registered.push({ hookName, handler, registration });
      }
    });

    expect(registered.map((entry) => entry.hookName)).toEqual([
      "before_agent_start",
      "message_received",
      "before_tool_call",
      "tool_result_persist",
      "message_sending",
      "agent_end"
    ]);

    for (const entry of registered) {
      expect(entry.registration?.name).toBe(
        `openclaw-guardrails.${entry.hookName}`
      );
      expect(typeof entry.registration?.description).toBe("string");
      expect(entry.registration?.description?.length).toBeGreaterThan(0);
    }

    const beforeAgentStart = registered.find(
      (entry) => entry.hookName === "before_agent_start"
    );
    expect(beforeAgentStart).toBeDefined();

    const result = (await beforeAgentStart?.handler({
      agentId: "agent-1",
      systemPrompt: "You are a coding agent"
    })) as { systemPrompt?: string };

    expect(result.systemPrompt).toContain("Security policy (immutable)");
    expect(result.systemPrompt).toContain("You are a coding agent");
  });
});
