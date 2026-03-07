import { evaluateAuthorization } from "../authorization.js";
import { resolvePrincipalContext } from "../identity.js";
import { toolToAction } from "../permissions.js";
import { REASON_CODES } from "../reason-codes.js";
import { AUDIT_EVENT_TYPES } from "../types.js";
import type { RuleHit } from "../types.js";
import type { PrincipalAuthzResult } from "./types.js";
import type { DetectorContext } from "./types.js";

export function detectPrincipalAuthz(context: DetectorContext): PrincipalAuthzResult {
  const { event, config, roleStore } = context;
  const resolution = resolvePrincipalContext(event.metadata, config);

  event.metadata.principal = resolution.principal;
  event.metadata.principalMissingContext = resolution.missingContext;

  // If a RoleStore is available AND the event has bot identification metadata,
  // use dual-authorization. Otherwise, fall back to config-based authorization.
  const botPlatform = event.metadata.botPlatform as string | undefined;
  const botPlatformId = event.metadata.botPlatformId as string | undefined;
  const senderPlatform = event.metadata.senderPlatform as string | undefined;

  if (roleStore && botPlatform && botPlatformId && senderPlatform && resolution.principal.senderId !== "unknown-sender") {
    return detectWithStore(context, roleStore, senderPlatform, resolution.principal.senderId, botPlatform, botPlatformId);
  }

  // Fallback: existing config-based authorization
  const authz = evaluateAuthorization(event, config);
  return {
    hits: authz.hits,
    principal: resolution.principal,
    approvalRequirement: authz.approvalRequirement
  };
}

function detectWithStore(
  context: DetectorContext,
  roleStore: NonNullable<DetectorContext["roleStore"]>,
  senderPlatform: string,
  senderId: string,
  botPlatform: string,
  botPlatformId: string
): PrincipalAuthzResult {
  const { event } = context;
  const channelId = event.metadata.principal?.channelId;
  const hits: RuleHit[] = [];
  const actorUserId = roleStore.resolveUserId(senderPlatform, senderId);
  const authCtx = { senderPlatform, senderId, botPlatform, botPlatformId, platformChannelId: channelId };

  // For before_tool_call, check specific tool permission
  if (event.phase === "before_tool_call" && event.toolName) {
    const perm = { category: "tool_use", action: toolToAction(event.toolName) };
    const result = roleStore.checkPermission(authCtx, perm);

    if (!result.allowed) {
      const reasonCode =
        result.deniedBy === "bot_capability"
          ? REASON_CODES.RBAC_BOT_CAPABILITY_DENIED
          : result.deniedBy === "bot_access_policy"
            ? REASON_CODES.RBAC_BOT_ACCESS_DENIED
            : REASON_CODES.RBAC_USER_DENIED;

      hits.push({
        ruleId: `rbac.dual_auth.${result.deniedBy ?? "user_rbac"}`,
        reasonCode,
        decision: "DENY",
        weight: 0.95
      });

      roleStore.logDecision({
        actorPlatform: senderPlatform,
        actorPlatformId: senderId,
        actorUserId,
        imChannelId: channelId,
        eventType: result.deniedBy === "bot_access_policy" ? AUDIT_EVENT_TYPES.AUTHZ_DENY_ACCESS
          : result.deniedBy === "bot_capability" ? AUDIT_EVENT_TYPES.AUTHZ_DENY_BOT
          : AUDIT_EVENT_TYPES.AUTHZ_DENY_USER,
        decision: "deny",
        deniedBy: result.deniedBy === "bot_access_policy" ? "bot_access_policy" : result.deniedBy === "bot_capability" ? "bot_capability" : "user_rbac",
        permissionCategory: perm.category,
        permissionAction: perm.action
      });

      return { hits, principal: event.metadata.principal };
    }

    roleStore.logDecision({
      actorPlatform: senderPlatform,
      actorPlatformId: senderId,
      actorUserId,
      imChannelId: channelId,
      eventType: AUDIT_EVENT_TYPES.AUTHZ_ALLOW,
      decision: "allow",
      permissionCategory: perm.category,
      permissionAction: perm.action
    });
  }

  // Also run the existing config-based checks for group channel rules, etc.
  // These cover mention requirements, unknown sender blocking, etc.
  const authz = evaluateAuthorization(event, context.config);
  hits.push(...authz.hits);

  return {
    hits,
    principal: event.metadata.principal,
    approvalRequirement: authz.approvalRequirement
  };
}
