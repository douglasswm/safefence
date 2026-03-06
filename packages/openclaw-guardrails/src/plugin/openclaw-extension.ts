/**
 * OpenClaw plugin entry point for @safefence/openclaw-guardrails.
 *
 * Uses the real OpenClaw plugin API:
 * - `api.on()` for typed hooks (return values are honoured)
 * - `api.pluginConfig` for validated config
 * - `api.logger` for structured logging
 * - `api.registerCommand()` for the /approve command
 */

import type { GuardrailsConfig } from "../core/types.js";
import { redactWithPatterns } from "../redaction/redact.js";
import { createDefaultConfig, mergeConfig } from "../rules/default-policy.js";
import { createOpenClawGuardrailsPlugin } from "./openclaw-adapter.js";
import {
  mapBeforeAgentStart,
  mapMessageReceived,
  mapBeforeToolCall,
  mapToolResultPersist,
  mapMessageSending,
  mapAgentEnd,
  mapToBeforeAgentStartResult,
  mapToBeforeToolCallResult,
  mapToMessageSendingResult,
  type BeforeAgentStartEvent,
  type BeforeAgentStartContext,
  type MessageReceivedEvent,
  type MessageReceivedContext,
  type BeforeToolCallEvent,
  type BeforeToolCallContext,
  type ToolResultPersistEvent,
  type ToolResultPersistContext,
  type ToolResultPersistResult,
  type MessageSendingEvent,
  type MessageSendingContext,
  type AgentEndEvent,
  type AgentEndContext,
} from "./event-adapter.js";

// ---------------------------------------------------------------------------
// Structural types for the OpenClaw plugin API.
//
// We use structural typing so that the package compiles without a hard import
// of the `openclaw` module at build time. At runtime, OpenClaw's jiti alias
// resolves `openclaw/plugin-sdk` if needed, and the structural shape is
// compatible with the real `OpenClawPluginApi`.
// ---------------------------------------------------------------------------

interface PluginLogger {
  debug?: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

interface PluginCommandContext {
  senderId?: string;
  args?: string;
  commandBody: string;
  isAuthorizedSender: boolean;
}

interface PluginCommandResult {
  text?: string;
}

interface PluginApi {
  id: string;
  name: string;
  config: unknown;
  pluginConfig?: Record<string, unknown>;
  logger: PluginLogger;
  resolvePath: (input: string) => string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on: (hookName: string, handler: (...args: any[]) => any, opts?: { priority?: number }) => void;
  registerCommand: (command: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: PluginCommandContext) => PluginCommandResult | Promise<PluginCommandResult>;
  }) => void;
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const plugin = {
  id: "openclaw-guardrails",
  name: "OpenClaw Guardrails",
  version: "0.6.0",

  register(api: PluginApi) {
    const rawConfig = (api.pluginConfig ?? {}) as Partial<GuardrailsConfig>;
    const log = api.logger;
    const mergedConfig = mergeConfig(
      createDefaultConfig(rawConfig.workspaceRoot ?? process.cwd()),
      rawConfig,
    );

    const guardrails = createOpenClawGuardrailsPlugin(rawConfig);

    log.info(`[guardrails] plugin registered (v${guardrails.version}, mode=${mergedConfig.mode})`);

    // ------------------------------------------------------------------
    // before_agent_start — inject security policy prompt
    // ------------------------------------------------------------------
    api.on("before_agent_start", async (
      event: BeforeAgentStartEvent,
      ctx: BeforeAgentStartContext,
    ) => {
      const oclCtx = mapBeforeAgentStart(event, ctx);
      const result = await guardrails.hooks.before_agent_start(oclCtx);
      log.debug?.(`[guardrails:before_agent_start] decision=${result.guardrails?.decision?.decision}`);
      return mapToBeforeAgentStartResult(result);
    });

    // ------------------------------------------------------------------
    // message_received — observe-only (cannot block via return value)
    // Audit violations but enforcement is deferred to before_tool_call.
    // ------------------------------------------------------------------
    api.on("message_received", async (
      event: MessageReceivedEvent,
      ctx: MessageReceivedContext,
    ) => {
      const oclCtx = mapMessageReceived(event, ctx);
      const result = await guardrails.hooks.message_received(oclCtx);
      if (result.blocked) {
        log.warn(`[guardrails:message_received] inbound content would be blocked: ${result.reasonCodes?.join(", ")}`);
      }
      // void return — message_received cannot block in OpenClaw
    });

    // ------------------------------------------------------------------
    // before_tool_call — authorize and gate tool calls
    // ------------------------------------------------------------------
    api.on("before_tool_call", async (
      event: BeforeToolCallEvent,
      ctx: BeforeToolCallContext,
    ) => {
      const oclCtx = mapBeforeToolCall(event, ctx);
      const result = await guardrails.hooks.before_tool_call(oclCtx);
      log.debug?.(`[guardrails:before_tool_call] tool=${event.toolName} decision=${result.guardrails?.decision?.decision}`);
      return mapToBeforeToolCallResult(result);
    });

    // ------------------------------------------------------------------
    // tool_result_persist — sanitize tool output before persistence
    //
    // IMPORTANT: This hook is synchronous in OpenClaw (returns result | void,
    // no Promise). The guardrails engine is async (external validators,
    // network checks). We fire the engine evaluation asynchronously for
    // audit/metrics tracking but cannot use its result for redaction here.
    //
    // Outbound content redaction is still enforced by the async
    // `message_sending` hook, which catches leaks before they reach users.
    // ------------------------------------------------------------------
    // Pre-compile redaction patterns once (config is immutable after merge).
    const allRedactionPatterns = [
      ...mergedConfig.redaction.secretPatterns,
      ...mergedConfig.redaction.piiPatterns,
    ];
    const redactionReplacement = mergedConfig.redaction.replacement;

    api.on("tool_result_persist", (
      event: ToolResultPersistEvent,
      ctx: ToolResultPersistContext,
    ) => {
      const oclCtx = mapToolResultPersist(event, ctx);

      // Fire engine evaluation async for audit trail and metrics.
      // Result is intentionally not awaited (sync hook constraint).
      guardrails.hooks.tool_result_persist(oclCtx).catch((err: unknown) => {
        log.error(`[guardrails:tool_result_persist] async audit failed: ${String(err)}`);
      });

      // Sync redaction: reuse content already extracted by the mapper.
      const content = oclCtx.output;
      if (content && allRedactionPatterns.length > 0) {
        const { redacted } = redactWithPatterns(content, allRedactionPatterns, redactionReplacement);
        if (redacted !== content) {
          return { message: { ...event.message, content: redacted } } satisfies ToolResultPersistResult;
        }
      }

      return {};
    });

    // ------------------------------------------------------------------
    // message_sending — gate outbound agent responses
    // ------------------------------------------------------------------
    api.on("message_sending", async (
      event: MessageSendingEvent,
      ctx: MessageSendingContext,
    ) => {
      const oclCtx = mapMessageSending(event, ctx);
      const result = await guardrails.hooks.message_sending(oclCtx);
      log.debug?.(`[guardrails:message_sending] decision=${result.guardrails?.decision?.decision}`);
      return mapToMessageSendingResult(result);
    });

    // ------------------------------------------------------------------
    // agent_end — observe-only (publish metrics)
    // ------------------------------------------------------------------
    api.on("agent_end", async (
      event: AgentEndEvent,
      ctx: AgentEndContext,
    ) => {
      const oclCtx = mapAgentEnd(event, ctx);
      const result = await guardrails.hooks.agent_end(oclCtx);
      const summary = result.metadata?.guardrailsSummary as Record<string, unknown> | undefined;
      if (summary) {
        log.info(`[guardrails:agent_end] summary: total=${summary.total} blocked=${summary.blocked} redacted=${summary.redacted}`);
      }
      // void return — agent_end is observe-only
    });

    // ------------------------------------------------------------------
    // /approve command — approve a guardrail-gated action
    // ------------------------------------------------------------------
    api.registerCommand({
      name: "approve",
      description: "Approve a guardrail-gated action by request ID",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx: PluginCommandContext) => {
        const requestId = ctx.args?.trim();
        if (!requestId) {
          return { text: "Usage: /approve <request-id>" };
        }

        const senderId = ctx.senderId ?? "unknown";
        if (!ctx.isAuthorizedSender) {
          return { text: "Only authorized senders (owner/admin) can approve requests." };
        }
        const token = guardrails.approveRequest(requestId, senderId, "owner");

        if (token) {
          log.info(`[guardrails:approve] request ${requestId} approved by ${senderId}`);
          return { text: `Approved. Token: ${token}` };
        }

        return { text: `Approval failed for request ${requestId}. It may have expired or already been processed.` };
      },
    });
  },
};

export default plugin;
