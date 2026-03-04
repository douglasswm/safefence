import { isObject, asRecord } from "../core/event-utils.js";
import type { GuardrailsConfig } from "../core/types.js";
import {
  createOpenClawGuardrailsPlugin,
  type OpenClawContext,
  type OpenClawHookResult
} from "./openclaw-adapter.js";

const PLUGIN_ID = "openclaw-guardrails";

interface HookRegistration {
  name?: string;
  description?: string;
}

interface OpenClawPluginApi {
  config?: unknown;
  registerHook?: (
    hookName: string,
    handler: (context: unknown) => Promise<OpenClawHookResult> | OpenClawHookResult,
    registration?: HookRegistration
  ) => void;
  logger?: {
    warn?: (message: string) => void;
  };
}

function isGuardrailsConfig(value: Record<string, unknown>): boolean {
  const knownKeys = [
    "mode",
    "failClosed",
    "workspaceRoot",
    "allow",
    "deny",
    "redaction",
    "limits",
    "pathPolicy",
    "supplyChain",
    "retrievalTrust",
    "principal",
    "authorization",
    "approval",
    "tenancy",
    "outboundGuard",
    "rollout",
    "monitoring"
  ];

  return knownKeys.some((key) => key in value);
}

function getPluginConfig(rawConfig: unknown): Partial<GuardrailsConfig> {
  if (!isObject(rawConfig)) {
    return {};
  }

  const plugins = rawConfig.plugins;
  if (isObject(plugins)) {
    const entries = plugins.entries;
    if (isObject(entries)) {
      const entry = entries[PLUGIN_ID];
      if (isObject(entry) && isObject(entry.config)) {
        return entry.config as Partial<GuardrailsConfig>;
      }
    }
  }

  if (isGuardrailsConfig(rawConfig)) {
    return rawConfig as Partial<GuardrailsConfig>;
  }

  return {};
}

function registerHook(
  api: OpenClawPluginApi,
  hookName: string,
  handler: (context: OpenClawContext) => Promise<OpenClawHookResult>,
  description: string
): void {
  api.registerHook?.(hookName, (context: unknown) => handler(asRecord(context) as OpenClawContext), {
    name: `${PLUGIN_ID}.${hookName}`,
    description
  });
}

export function registerOpenClawGuardrails(api: OpenClawPluginApi): void {
  if (typeof api.registerHook !== "function") {
    api.logger?.warn?.("[openclaw-guardrails] registerHook API is unavailable.");
    return;
  }

  const plugin = createOpenClawGuardrailsPlugin(getPluginConfig(api.config));

  registerHook(
    api,
    "before_agent_start",
    plugin.hooks.before_agent_start,
    "Inject immutable security policy prompt before agent execution."
  );
  registerHook(
    api,
    "message_received",
    plugin.hooks.message_received,
    "Evaluate inbound message content for prompt injection and data leaks."
  );
  registerHook(
    api,
    "before_tool_call",
    plugin.hooks.before_tool_call,
    "Authorize and gate tool calls before execution."
  );
  registerHook(
    api,
    "tool_result_persist",
    plugin.hooks.tool_result_persist,
    "Sanitize tool output before persistence."
  );
  registerHook(
    api,
    "message_sending",
    plugin.hooks.message_sending,
    "Gate outbound agent responses for system prompt leaks and sensitive data."
  );
  registerHook(
    api,
    "agent_end",
    plugin.hooks.agent_end,
    "Publish aggregated guardrails summary and monitoring metrics."
  );
}

export default registerOpenClawGuardrails;
