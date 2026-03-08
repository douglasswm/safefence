import type { RoleStore } from "./role-store.js";
import type {
  ChannelType,
  GuardMetadata,
  GuardrailsConfig,
  PrincipalContext,
  PrincipalRole
} from "./types.js";

export const UNKNOWN_SENDER = "unknown-sender";
export const UNKNOWN_CONVERSATION = "unknown-conversation";

export interface PrincipalResolution {
  principal: PrincipalContext;
  missingContext: boolean;
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  return undefined;
}

function normalizeRole(value: unknown): PrincipalRole | undefined {
  switch (value) {
    case "owner":
    case "admin":
    case "member":
    case "unknown":
      return value;
    default:
      return undefined;
  }
}

function normalizeChannelType(value: unknown): ChannelType {
  switch (value) {
    case "dm":
    case "group":
    case "thread":
      return value;
    default:
      return "unknown";
  }
}

/**
 * Parse a compound senderId (e.g. "telegram:12345") into platform and platformId.
 * Returns undefined if the format doesn't match.
 */
export function parseSenderId(senderId: string): { platform: string; platformId: string } | undefined {
  const idx = senderId.indexOf(":");
  if (idx <= 0 || idx === senderId.length - 1) return undefined;
  return { platform: senderId.slice(0, idx), platformId: senderId.slice(idx + 1) };
}

function inferRole(
  senderId: string | undefined,
  explicitRole: PrincipalRole | undefined,
  config: GuardrailsConfig,
  roleStore?: RoleStore
): PrincipalRole {
  // Privileged roles (owner/admin) MUST be derived from trusted sources,
  // never from caller-supplied metadata. This prevents role spoofing
  // where an attacker sets metadata.role = "owner" to bypass guardrails.
  if (!senderId) {
    return "unknown";
  }

  // When a RoleStore is available, query it first for dynamic role resolution.
  // This allows owners/admins to be managed via RBAC without gateway restarts.
  if (roleStore) {
    const parsed = parseSenderId(senderId);
    if (parsed) {
      const storeRole = roleStore.resolveRole(parsed.platform, parsed.platformId);
      if (storeRole === "owner" || storeRole === "admin") {
        return storeRole;
      }
    }
  }

  // Fall back to static config for bootstrap / non-RBAC deployments.
  if (config.principal.ownerIds.includes(senderId)) {
    return "owner";
  }

  if (config.principal.adminIds.includes(senderId)) {
    return "admin";
  }

  // Caller-supplied role is only trusted for non-privileged values.
  // "owner" and "admin" from metadata are downgraded to "member".
  if (explicitRole && explicitRole !== "unknown" && explicitRole !== "owner" && explicitRole !== "admin") {
    return explicitRole;
  }

  return "member";
}

function pickSenderId(metadata: GuardMetadata): string | undefined {
  return (
    asString(metadata.principal?.senderId) ??
    asString(metadata.senderId) ??
    asString(metadata.userId) ??
    asString(metadata.fromId) ??
    asString(metadata.actorId)
  );
}

function pickConversationId(metadata: GuardMetadata): string {
  return (
    asString(metadata.principal?.conversationId) ??
    asString(metadata.conversationId) ??
    asString(metadata.sessionKey) ??
    asString(metadata.channelId) ??
    UNKNOWN_CONVERSATION
  );
}

export function resolvePrincipalContext(
  metadata: GuardMetadata,
  config: GuardrailsConfig,
  roleStore?: RoleStore
): PrincipalResolution {
  const senderId = pickSenderId(metadata);
  const senderHandle =
    asString(metadata.principal?.senderHandle) ??
    asString(metadata.senderHandle) ??
    asString(metadata.username);
  const explicitRole =
    normalizeRole(metadata.principal?.role) ?? normalizeRole(metadata.role);
  const role = inferRole(senderId, explicitRole, config, roleStore);
  const channelType = normalizeChannelType(
    metadata.principal?.channelType ?? metadata.channelType
  );
  const mentionedAgent =
    asBoolean(metadata.principal?.mentionedAgent) ??
    asBoolean(metadata.mentionedAgent);
  const pairedDevice =
    asBoolean(metadata.principal?.pairedDevice) ??
    asBoolean(metadata.pairedDevice);
  const channelId =
    asString(metadata.principal?.channelId) ?? asString(metadata.channelId);

  const principal: PrincipalContext = {
    senderId: senderId ?? UNKNOWN_SENDER,
    senderHandle,
    role,
    channelId,
    conversationId: pickConversationId(metadata),
    channelType,
    mentionedAgent,
    pairedDevice
  };

  const hasAnyIdentitySignal =
    Boolean(metadata.principal?.senderId) ||
    Boolean(asString(metadata.senderId)) ||
    Boolean(asString(metadata.userId)) ||
    Boolean(asString(metadata.fromId)) ||
    Boolean(asString(metadata.actorId));

  return {
    principal,
    missingContext: !hasAnyIdentitySignal
  };
}
