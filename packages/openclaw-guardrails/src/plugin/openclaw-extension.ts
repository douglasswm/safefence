/**
 * OpenClaw plugin entry point for @safefence/openclaw-guardrails.
 *
 * Uses the real OpenClaw plugin API:
 * - `api.on()` for typed hooks (return values are honoured)
 * - `api.pluginConfig` for validated config
 * - `api.logger` for structured logging
 * - `api.registerCommand()` for the /approve command
 */

import { randomUUID as generateUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { ConfigRoleStore } from "../core/config-role-store.js";
import { extractFlag } from "../utils/args.js";
import type { RoleStore } from "../core/role-store.js";
import type { GuardrailsConfig } from "../core/types.js";
import { redactWithPatterns } from "../redaction/redact.js";
import { createDefaultConfig, mergeConfig } from "../rules/default-policy.js";
import { createOpenClawGuardrailsPlugin } from "./openclaw-adapter.js";
import { PLUGIN_VERSION } from "./version.js";
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
  version: PLUGIN_VERSION,

  register(api: PluginApi) {
    const rawConfig = (api.pluginConfig ?? {}) as Partial<GuardrailsConfig>;
    const log = api.logger;
    const workspaceRoot = rawConfig.workspaceRoot ?? process.cwd();
    const fullConfig = mergeConfig(createDefaultConfig(workspaceRoot), rawConfig);

    // Initialize RoleStore based on config
    let roleStore: RoleStore | undefined;
    const rbacConfig = rawConfig.rbacStore;
    if (rbacConfig?.enabled) {
      try {
        const { SqliteRoleStore } = require("../core/sqlite-role-store.js") as { SqliteRoleStore: new (dbPath: string, auditDbPath: string, config?: GuardrailsConfig) => RoleStore };
        const dbPath = rbacConfig.dbPath ?? `${workspaceRoot}/.safefence/rbac.db`;
        const auditDbPath = rbacConfig.auditDbPath ?? `${workspaceRoot}/.safefence/audit.db`;

        // Ensure directory exists
        mkdirSync(dirname(dbPath), { recursive: true });

        roleStore = new SqliteRoleStore(dbPath, auditDbPath, fullConfig);
        log.info(`[guardrails] RBAC store initialized (${dbPath})`);
      } catch (err: unknown) {
        log.warn(`[guardrails] Failed to initialize RBAC store, falling back to config: ${String(err)}`);
        roleStore = undefined;
      }
    }

    // If no SQLite store, use config-based fallback
    if (!roleStore) {
      roleStore = new ConfigRoleStore(fullConfig);
    }

    const guardrails = createOpenClawGuardrailsPlugin({ mergedConfig: fullConfig, roleStore });
    const mergedConfig = guardrails.config;

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

    // ------------------------------------------------------------------
    // /sf command — RBAC management commands
    // ------------------------------------------------------------------
    api.registerCommand({
      name: "sf",
      description: "SafeFence RBAC management commands",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx: PluginCommandContext) => {
        return handleSfCommand(ctx, roleStore, mergedConfig, log);
      },
    });
  },
};

/** Commands that require specific admin permissions. */
const COMMAND_PERMISSIONS: Record<string, { category: string; action: string }> = {
  role: { category: "admin", action: "role_manage" },
  assign: { category: "admin", action: "role_assign" },
  revoke: { category: "admin", action: "role_assign" },
  bot: { category: "admin", action: "bot_manage" },
  channel: { category: "admin", action: "channel_manage" },
};

/** Read-only commands that only need the sender to be authorized. */
const READ_ONLY_COMMANDS = new Set(["who", "audit", "help"]);

function checkSfPermission(
  senderId: string,
  command: string,
  config: GuardrailsConfig
): string | null {
  // Read-only commands only need the sender to be an authorized sender (owner/admin)
  if (READ_ONLY_COMMANDS.has(command)) return null;

  const requiredPerm = COMMAND_PERMISSIONS[command];
  if (!requiredPerm) return null; // unknown commands will error later

  // Check if sender is owner (has all permissions)
  if (config.principal.ownerIds.includes(senderId)) return null;

  // Check if sender is admin (limited permissions)
  if (config.principal.adminIds.includes(senderId)) {
    // Admins can assign roles but not manage roles/bots/channels
    if (requiredPerm.action === "role_assign") return null;
    return `Permission denied: ${requiredPerm.category}:${requiredPerm.action} requires owner access.`;
  }

  return `Permission denied: only owners and admins can use /sf ${command}.`;
}

function handleSfCommand(
  ctx: PluginCommandContext,
  store: RoleStore,
  config: GuardrailsConfig,
  log: PluginLogger
): PluginCommandResult {
  const body = (ctx.commandBody ?? ctx.args ?? "").trim();
  const parts = body.split(/\s+/);
  const sub = parts[0]?.toLowerCase();
  const rest = parts.slice(1);

  if (!sub) {
    return { text: sfHelp() };
  }

  // Authorization check: sender must be owner/admin for management commands
  const senderId = ctx.senderId ?? "unknown";
  if (!ctx.isAuthorizedSender) {
    return { text: "Permission denied: only authorized senders can use /sf commands." };
  }

  const permError = checkSfPermission(senderId, sub, config);
  if (permError) {
    return { text: permError };
  }

  try {
    switch (sub) {
      case "role": return handleRoleCommand(rest, store, ctx);
      case "assign": return handleAssignCommand(rest, store, ctx);
      case "revoke": return handleRevokeCommand(rest, store, ctx);
      case "who": return handleWhoCommand(rest, store);
      case "bot": return handleBotCommand(rest, store, ctx);
      case "channel": return handleChannelCommand(rest, store, ctx);
      case "audit": return handleAuditCommand(rest, store);
      case "help": return { text: sfHelp() };
      default: return { text: `Unknown command: ${sub}\n\n${sfHelp()}` };
    }
  } catch (err: unknown) {
    log.error(`[guardrails:sf] command error: ${String(err)}`);
    return { text: `Error: ${err instanceof Error ? err.message : String(err)}` };
  }
}

function sfHelp(): string {
  return [
    "SafeFence RBAC Commands:",
    "  /sf role list|create|delete|permissions|grant-perm|revoke-perm",
    "  /sf assign <userId> <roleName> [--project <id>]",
    "  /sf revoke <assignmentId>",
    "  /sf who <userId>",
    "  /sf bot register|cap|access|list",
    "  /sf channel link|unlink",
    "  /sf audit [--bot <name>] [--limit N]",
    "  /sf help",
  ].join("\n");
}

function handleRoleCommand(args: string[], store: RoleStore, ctx: PluginCommandContext): PluginCommandResult {
  const action = args[0]?.toLowerCase();
  const projectId = extractFlag(args, "--project") ?? "default-project";

  switch (action) {
    case "list": {
      const roles = store.listRoles(projectId);
      if (roles.length === 0) return { text: "No roles found." };
      const lines = roles.map((r) =>
        `  ${r.name}${r.isSystem ? " (system)" : ""} — ${r.description ?? "no description"}`
      );
      return { text: `Roles in project ${projectId}:\n${lines.join("\n")}` };
    }
    case "create": {
      const name = args[1];
      if (!name) return { text: "Usage: /sf role create <name> [--description \"...\"]" };
      const description = extractFlag(args, "--description");
      const role = store.createRole(projectId, name, [], description ?? undefined, ctx.senderId);
      return { text: `Role created: ${role.name} (${role.id})` };
    }
    case "delete": {
      const name = args[1];
      if (!name) return { text: "Usage: /sf role delete <name>" };
      const roles = store.listRoles(projectId);
      const role = roles.find((r) => r.name === name);
      if (!role) return { text: `Role not found: ${name}` };
      store.deleteRole(role.id);
      return { text: `Role deleted: ${name}` };
    }
    case "permissions": {
      const name = args[1];
      if (!name) return { text: "Usage: /sf role permissions <name>" };
      const roles = store.listRoles(projectId);
      const role = roles.find((r) => r.name === name);
      if (!role) return { text: `Role not found: ${name}` };
      const perms = store.getRolePermissions(role.id);
      if (perms.length === 0) return { text: `No permissions for role: ${name}` };
      const lines = perms.map((p) => `  ${p.permissionId} (${p.effect})`);
      return { text: `Permissions for ${name}:\n${lines.join("\n")}` };
    }
    case "grant-perm": {
      const roleName = args[1];
      const permId = args[2];
      if (!roleName || !permId) return { text: "Usage: /sf role grant-perm <role> <category:action>" };
      const roles = store.listRoles(projectId);
      const role = roles.find((r) => r.name === roleName);
      if (!role) return { text: `Role not found: ${roleName}` };
      store.grantRolePermission(role.id, permId, "allow");
      return { text: `Granted ${permId} to ${roleName}` };
    }
    case "revoke-perm": {
      const roleName = args[1];
      const permId = args[2];
      if (!roleName || !permId) return { text: "Usage: /sf role revoke-perm <role> <category:action>" };
      const roles = store.listRoles(projectId);
      const role = roles.find((r) => r.name === roleName);
      if (!role) return { text: `Role not found: ${roleName}` };
      store.revokeRolePermission(role.id, permId);
      return { text: `Revoked ${permId} from ${roleName}` };
    }
    default:
      return { text: "Usage: /sf role list|create|delete|permissions|grant-perm|revoke-perm" };
  }
}

function handleAssignCommand(args: string[], store: RoleStore, ctx: PluginCommandContext): PluginCommandResult {
  const userId = args[0];
  const roleName = args[1];
  if (!userId || !roleName) return { text: "Usage: /sf assign <userId> <roleName> [--project <id>] [--bot <botId>]" };

  const projectId = extractFlag(args, "--project") ?? "default-project";
  const botId = extractFlag(args, "--bot");
  const channelScope = args.includes("--channel");

  const roles = store.listRoles(projectId);
  const role = roles.find((r) => r.name === roleName);
  if (!role) return { text: `Role not found: ${roleName}` };

  store.ensureUser(userId);
  const scopeType = channelScope ? "im_channel" as const : "project" as const;
  const scopeId = channelScope ? (extractFlag(args, "--channel") ?? projectId) : projectId;

  const assignment = store.assignRole(userId, role.id, scopeType, scopeId, botId ?? undefined, ctx.senderId);
  return { text: `Assigned ${roleName} to ${userId} (${assignment.id})` };
}

function handleRevokeCommand(args: string[], store: RoleStore, _ctx: PluginCommandContext): PluginCommandResult {
  const assignmentId = args[0];
  if (!assignmentId) return { text: "Usage: /sf revoke <assignmentId>" };
  store.revokeRole(assignmentId);
  return { text: `Revoked assignment: ${assignmentId}` };
}

function handleWhoCommand(args: string[], store: RoleStore): PluginCommandResult {
  const userId = args[0];
  if (!userId) return { text: "Usage: /sf who <userId>" };

  const assignments = store.getUserAssignments(userId);
  if (assignments.length === 0) return { text: `No role assignments for: ${userId}` };

  const lines = assignments.map((a) => {
    const role = store.getRole(a.roleId);
    const botInfo = a.botInstanceId ? ` (bot: ${a.botInstanceId})` : "";
    const expiry = a.expiresAt ? ` expires: ${new Date(a.expiresAt).toISOString()}` : "";
    return `  ${role?.name ?? a.roleId} @ ${a.scopeType}:${a.scopeId}${botInfo}${expiry}`;
  });
  return { text: `Roles for ${userId}:\n${lines.join("\n")}` };
}

function handleBotCommand(args: string[], store: RoleStore, ctx: PluginCommandContext): PluginCommandResult {
  const action = args[0]?.toLowerCase();
  const projectId = extractFlag(args, "--project") ?? "default-project";

  switch (action) {
    case "register": {
      const name = args[1];
      const platform = extractFlag(args, "--platform") ?? "unknown";
      const botPlatformId = extractFlag(args, "--bot-id") ?? generateUUID();
      const ownerId = ctx.senderId ?? "unknown";
      store.ensureUser(ownerId);
      const bot = store.registerBot(projectId, ownerId, platform, botPlatformId, name);
      return { text: `Bot registered: ${bot.name ?? bot.id} (${bot.id})` };
    }
    case "cap": {
      const subAction = args[1]?.toLowerCase();
      if (subAction === "set") {
        const permId = args[2];
        const effect = args[3] as "allow" | "deny";
        const botId = extractFlag(args, "--bot");
        if (!botId || !permId || !effect) return { text: "Usage: /sf bot cap set <perm> allow|deny --bot <id>" };
        store.setBotCapability(botId, permId, effect);
        return { text: `Set ${permId} = ${effect} on bot ${botId}` };
      }
      if (subAction === "list") {
        const botId = extractFlag(args, "--bot");
        if (!botId) return { text: "Usage: /sf bot cap list --bot <id>" };
        const caps = store.getBotCapabilities(botId);
        if (caps.length === 0) return { text: "No explicit capabilities set (defaults to allow-all)." };
        const lines = caps.map((c) => `  ${c.permissionId}: ${c.effect}`);
        return { text: `Bot capabilities:\n${lines.join("\n")}` };
      }
      return { text: "Usage: /sf bot cap set|list" };
    }
    case "access": {
      const policy = args[1] as "owner_only" | "project_members" | "explicit" | undefined;
      const botId = extractFlag(args, "--bot");
      if (!botId || !policy) return { text: "Usage: /sf bot access <policy> --bot <id>" };
      store.setBotAccessPolicy(botId, policy);
      return { text: `Set access policy to ${policy} on bot ${botId}` };
    }
    case "list": {
      const bots = store.listBots(projectId);
      if (bots.length === 0) return { text: "No bots registered." };
      const lines = bots.map((b) =>
        `  ${b.name ?? b.id} (${b.platform}:${b.platformBotId ?? "?"}) policy=${b.accessPolicy}`
      );
      return { text: `Bots in project ${projectId}:\n${lines.join("\n")}` };
    }
    default:
      return { text: "Usage: /sf bot register|cap|access|list" };
  }
}

function handleChannelCommand(args: string[], store: RoleStore, _ctx: PluginCommandContext): PluginCommandResult {
  const action = args[0]?.toLowerCase();

  switch (action) {
    case "link": {
      const projectId = args[1] ?? extractFlag(args, "--project") ?? "default-project";
      const platform = extractFlag(args, "--platform") ?? "unknown";
      const platformChannelId = extractFlag(args, "--channel-id") ?? generateUUID();
      const displayName = extractFlag(args, "--name");
      const channelId = generateUUID();
      store.linkChannel(channelId, projectId, platform, platformChannelId, displayName ?? undefined);
      return { text: `Channel linked: ${displayName ?? channelId} -> project ${projectId}` };
    }
    case "unlink": {
      const platform = extractFlag(args, "--platform") ?? "unknown";
      const platformChannelId = extractFlag(args, "--channel-id");
      if (!platformChannelId) return { text: "Usage: /sf channel unlink --platform <p> --channel-id <id>" };
      store.unlinkChannel(platform, platformChannelId);
      return { text: `Channel unlinked: ${platform}:${platformChannelId}` };
    }
    default:
      return { text: "Usage: /sf channel link|unlink" };
  }
}

function handleAuditCommand(args: string[], store: RoleStore): PluginCommandResult {
  const botId = extractFlag(args, "--bot");
  const userId = extractFlag(args, "--user");
  const eventType = extractFlag(args, "--type");
  const limitStr = extractFlag(args, "--limit");
  const limit = limitStr ? parseInt(limitStr, 10) : 20;

  const entries = store.queryAudit({
    botInstanceId: botId ?? undefined,
    actorUserId: userId ?? undefined,
    eventType: eventType ?? undefined,
    limit,
  });

  if (entries.length === 0) return { text: "No audit entries found." };

  const lines = entries.map((e) => {
    const time = new Date(e.timestamp).toISOString();
    const perm = e.permissionCategory ? `${e.permissionCategory}:${e.permissionAction}` : "";
    return `  ${time} ${e.eventType} ${e.decision ?? ""} ${perm} ${e.deniedBy ? `(denied by ${e.deniedBy})` : ""}`.trim();
  });

  return { text: `Audit log (${entries.length} entries):\n${lines.join("\n")}` };
}

// extractFlag imported from ../utils/args.js

export default plugin;
