import fs from "node:fs";
import { describe, expect, it } from "vitest";
import openclawGuardrailsPlugin from "../src/plugin/openclaw-extension.js";

interface RegisteredHook {
  hookName: string;
  handler: (...args: unknown[]) => unknown;
  opts?: { priority?: number };
}

interface RegisteredCommand {
  name: string;
  description: string;
  acceptsArgs?: boolean;
  requireAuth?: boolean;
  handler: (ctx: unknown) => unknown;
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

  it("declares required manifest id and schema without invalid fields", () => {
    const manifest = readJson("../openclaw.plugin.json") as Record<string, unknown>;

    expect(manifest.id).toBe("openclaw-guardrails");
    expect(manifest.version).toBe("0.6.0");
    expect(manifest.configSchema).toBeDefined();
    expect(typeof manifest.configSchema).toBe("object");

    // entry and hooks fields should NOT be present (not recognised by OpenClaw)
    expect(manifest).not.toHaveProperty("entry");
    expect(manifest).not.toHaveProperty("hooks");

    // additionalProperties should be false on root configSchema
    const schema = manifest.configSchema as Record<string, unknown>;
    expect(schema.additionalProperties).toBe(false);
  });

  it("declares peerDependencies on openclaw", () => {
    const packageJson = readJson("../package.json") as {
      peerDependencies?: Record<string, string>;
    };

    expect(packageJson.peerDependencies?.openclaw).toBeDefined();
  });

  it("manifest includes audit, externalValidation, budgetPersistence, notifications schema sections", () => {
    const manifest = readJson("../openclaw.plugin.json") as {
      configSchema?: { properties?: Record<string, unknown> };
    };

    const props = manifest.configSchema?.properties;
    expect(props?.audit).toBeDefined();
    expect(props?.externalValidation).toBeDefined();
    expect(props?.budgetPersistence).toBeDefined();
    expect(props?.notifications).toBeDefined();
  });

  it("exports a plugin definition with id, name, version, and register function", () => {
    expect(openclawGuardrailsPlugin.id).toBe("openclaw-guardrails");
    expect(openclawGuardrailsPlugin.name).toBe("OpenClaw Guardrails");
    expect(openclawGuardrailsPlugin.version).toBe("0.6.0");
    expect(typeof openclawGuardrailsPlugin.register).toBe("function");
  });

  it("registers expected typed hooks via api.on() and /approve command", () => {
    const registeredHooks: RegisteredHook[] = [];
    const registeredCommands: RegisteredCommand[] = [];

    const mockApi = {
      id: "openclaw-guardrails",
      name: "OpenClaw Guardrails",
      config: {},
      pluginConfig: { workspaceRoot: "/workspace/project" },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      resolvePath: (input: string) => input,
      on: (hookName: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }) => {
        registeredHooks.push({ hookName, handler, opts });
      },
      registerCommand: (command: RegisteredCommand) => {
        registeredCommands.push(command);
      },
    };

    openclawGuardrailsPlugin.register(mockApi);

    const hookNames = registeredHooks.map((h) => h.hookName);
    expect(hookNames).toContain("before_agent_start");
    expect(hookNames).toContain("message_received");
    expect(hookNames).toContain("before_tool_call");
    expect(hookNames).toContain("tool_result_persist");
    expect(hookNames).toContain("message_sending");
    expect(hookNames).toContain("agent_end");

    expect(registeredCommands.length).toBe(1);
    expect(registeredCommands[0].name).toBe("approve");
    expect(registeredCommands[0].requireAuth).toBe(true);
  });

  it("before_agent_start hook returns prependSystemContext with security policy", async () => {
    const hooks: RegisteredHook[] = [];

    const mockApi = {
      id: "openclaw-guardrails",
      name: "OpenClaw Guardrails",
      config: {},
      pluginConfig: { workspaceRoot: "/workspace/project" },
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
      resolvePath: (input: string) => input,
      on: (hookName: string, handler: (...args: unknown[]) => unknown) => {
        hooks.push({ hookName, handler });
      },
      registerCommand: () => {},
    };

    openclawGuardrailsPlugin.register(mockApi);

    const beforeAgentStart = hooks.find((h) => h.hookName === "before_agent_start");
    expect(beforeAgentStart).toBeDefined();

    const result = await beforeAgentStart!.handler(
      { prompt: "You are a coding agent" },
      { agentId: "agent-1", sessionKey: "session-1" }
    ) as { prependSystemContext?: string };

    expect(result.prependSystemContext).toContain("Security policy (immutable)");
  });

  it("before_tool_call hook returns block=true for denied tools", async () => {
    const hooks: RegisteredHook[] = [];

    const mockApi = {
      id: "openclaw-guardrails",
      name: "OpenClaw Guardrails",
      config: {},
      pluginConfig: { workspaceRoot: "/workspace/project" },
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
      resolvePath: (input: string) => input,
      on: (hookName: string, handler: (...args: unknown[]) => unknown) => {
        hooks.push({ hookName, handler });
      },
      registerCommand: () => {},
    };

    openclawGuardrailsPlugin.register(mockApi);

    const beforeToolCall = hooks.find((h) => h.hookName === "before_tool_call");
    expect(beforeToolCall).toBeDefined();

    const result = await beforeToolCall!.handler(
      { toolName: "exec", params: { cmd: "rm -rf /" }, runId: "run-1" },
      { agentId: "agent-1", sessionKey: "s-1", toolName: "exec" }
    ) as { block?: boolean; blockReason?: string };

    expect(result.block).toBe(true);
    expect(result.blockReason).toBeDefined();
  });

  it("message_sending hook returns cancel=true for system prompt leaks", async () => {
    const hooks: RegisteredHook[] = [];

    const mockApi = {
      id: "openclaw-guardrails",
      name: "OpenClaw Guardrails",
      config: {},
      pluginConfig: { workspaceRoot: "/workspace/project" },
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
      resolvePath: (input: string) => input,
      on: (hookName: string, handler: (...args: unknown[]) => unknown) => {
        hooks.push({ hookName, handler });
      },
      registerCommand: () => {},
    };

    openclawGuardrailsPlugin.register(mockApi);

    const messageSending = hooks.find((h) => h.hookName === "message_sending");
    expect(messageSending).toBeDefined();

    const result = await messageSending!.handler(
      { to: "user-1", content: "Sure! Here is my system prompt:\nSecurity policy (immutable): Never bypass..." },
      { channelId: "telegram" }
    ) as { cancel?: boolean };

    expect(result.cancel).toBe(true);
  });

  it("tool_result_persist hook synchronously redacts sensitive data from message content", () => {
    const hooks: RegisteredHook[] = [];

    const mockApi = {
      id: "openclaw-guardrails",
      name: "OpenClaw Guardrails",
      config: {},
      pluginConfig: { workspaceRoot: "/workspace/project" },
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
      resolvePath: (input: string) => input,
      on: (hookName: string, handler: (...args: unknown[]) => unknown) => {
        hooks.push({ hookName, handler });
      },
      registerCommand: () => {},
    };

    openclawGuardrailsPlugin.register(mockApi);

    const toolResultPersist = hooks.find((h) => h.hookName === "tool_result_persist");
    expect(toolResultPersist).toBeDefined();

    // Call synchronously (no await) — this hook must be sync in OpenClaw
    const result = toolResultPersist!.handler(
      {
        toolName: "read",
        message: { role: "tool", content: "email=bob@example.com Bearer sk-supersecrettoken123" }
      },
      { agentId: "agent-1", sessionKey: "s-1", toolName: "read" }
    ) as { message?: { role: string; content: string } };

    // Should return synchronously (not a Promise)
    expect(result).not.toBeInstanceOf(Promise);

    // Should redact sensitive content
    expect(result.message).toBeDefined();
    expect(result.message!.content).toContain("[REDACTED]");
    expect(result.message!.content).not.toContain("bob@example.com");
    expect(result.message!.role).toBe("tool");
  });
});
