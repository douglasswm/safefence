/**
 * Event adapter layer: maps between OpenClaw typed hook events and the
 * plugin's internal OpenClawContext / GuardDecision types.
 *
 * OpenClaw typed hooks provide structured (event, ctx) pairs per hook.
 * The guardrails engine expects a flat OpenClawContext. This module bridges
 * the two shapes so the core engine can remain unchanged.
 */

import type { OpenClawContext, OpenClawHookResult } from "./openclaw-adapter.js";

// ---------------------------------------------------------------------------
// OpenClaw hook event/context types (structural — no import dependency)
// ---------------------------------------------------------------------------

export interface BeforeAgentStartEvent {
  prompt: string;
  messages?: unknown[];
}

export interface BeforeAgentStartContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  messageProvider?: string;
  trigger?: string;
  channelId?: string;
}

export interface BeforeAgentStartResult {
  systemPrompt?: string;
  prependContext?: string;
  prependSystemContext?: string;
  appendSystemContext?: string;
  modelOverride?: string;
  providerOverride?: string;
}

export interface MessageReceivedEvent {
  from: string;
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export interface MessageReceivedContext {
  channelId: string;
  accountId?: string;
  conversationId?: string;
}

export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

export interface BeforeToolCallContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName: string;
  toolCallId?: string;
}

export interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

export interface ToolResultPersistEvent {
  toolName?: string;
  toolCallId?: string;
  message: { role: string; content?: unknown; [key: string]: unknown };
  isSynthetic?: boolean;
}

export interface ToolResultPersistContext {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
}

export interface ToolResultPersistResult {
  message?: { role: string; content?: unknown; [key: string]: unknown };
}

export interface MessageSendingEvent {
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface MessageSendingContext {
  channelId: string;
  accountId?: string;
  conversationId?: string;
}

export interface MessageSendingResult {
  content?: string;
  cancel?: boolean;
}

export interface AgentEndEvent {
  messages: unknown[];
  success: boolean;
  error?: string;
  durationMs?: number;
}

export type AgentEndContext = BeforeAgentStartContext;

// ---------------------------------------------------------------------------
// Event → OpenClawContext mappers
// ---------------------------------------------------------------------------

export function mapBeforeAgentStart(
  event: BeforeAgentStartEvent,
  ctx: BeforeAgentStartContext,
): OpenClawContext {
  return {
    agentId: ctx.agentId,
    prompt: event.prompt,
    channelId: ctx.channelId,
    conversationId: ctx.sessionKey,
  };
}

export function mapMessageReceived(
  event: MessageReceivedEvent,
  ctx: MessageReceivedContext,
): OpenClawContext {
  return {
    agentId: undefined,
    senderId: event.from,
    content: event.content,
    channelId: ctx.channelId,
    conversationId: ctx.conversationId,
    metadata: event.metadata,
  };
}

export function mapBeforeToolCall(
  event: BeforeToolCallEvent,
  ctx: BeforeToolCallContext,
): OpenClawContext {
  return {
    agentId: ctx.agentId,
    toolName: event.toolName,
    args: event.params,
    conversationId: ctx.sessionKey,
  };
}

export function mapToolResultPersist(
  event: ToolResultPersistEvent,
  ctx: ToolResultPersistContext,
): OpenClawContext {
  const content = typeof event.message?.content === "string"
    ? event.message.content
    : undefined;
  return {
    agentId: ctx.agentId,
    toolName: event.toolName ?? ctx.toolName,
    output: content,
    conversationId: ctx.sessionKey,
  };
}

export function mapMessageSending(
  event: MessageSendingEvent,
  ctx: MessageSendingContext,
): OpenClawContext {
  return {
    agentId: undefined,
    content: event.content,
    channelId: ctx.channelId,
    conversationId: ctx.conversationId,
    metadata: event.metadata,
  };
}

export function mapAgentEnd(
  event: AgentEndEvent,
  ctx: AgentEndContext,
): OpenClawContext {
  return {
    agentId: ctx.agentId,
    conversationId: ctx.sessionKey,
    metadata: {
      success: event.success,
      error: event.error,
      durationMs: event.durationMs,
    },
  };
}

// ---------------------------------------------------------------------------
// GuardDecision / OpenClawHookResult → hook-specific result mappers
// ---------------------------------------------------------------------------

export function mapToBeforeAgentStartResult(
  hookResult: OpenClawHookResult,
): BeforeAgentStartResult {
  const result: BeforeAgentStartResult = {};

  if (typeof hookResult.systemPrompt === "string") {
    result.prependSystemContext = hookResult.systemPrompt;
  }

  return result;
}

export function mapToBeforeToolCallResult(
  hookResult: OpenClawHookResult,
): BeforeToolCallResult {
  if (hookResult.blocked) {
    const reason = hookResult.reasonCodes?.join(", ") ?? "guardrail_denied";
    return { block: true, blockReason: `[guardrails] ${reason}` };
  }
  return {};
}

export function mapToMessageSendingResult(
  hookResult: OpenClawHookResult,
): MessageSendingResult {
  if (hookResult.blocked || hookResult.cancel) {
    return { cancel: true };
  }

  const redactedContent = hookResult.guardrails?.decision?.redactedContent;
  if (redactedContent) {
    return { content: redactedContent };
  }

  return {};
}

export function mapToToolResultPersistResult(
  hookResult: OpenClawHookResult,
  originalEvent: ToolResultPersistEvent,
): ToolResultPersistResult {
  const redacted = hookResult.guardrails?.decision?.redactedContent;
  if (redacted) {
    return {
      message: {
        ...originalEvent.message,
        content: redacted,
      },
    };
  }

  if (hookResult.blocked) {
    return {
      message: {
        ...originalEvent.message,
        content: "[guardrails] content blocked",
      },
    };
  }

  return {};
}
