import type {
  ChannelType,
  GuardMetadata,
  GuardrailsConfig,
  PrincipalContext,
  PrincipalRole
} from "./types.js";

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

function inferRole(
  senderId: string | undefined,
  explicitRole: PrincipalRole | undefined,
  config: GuardrailsConfig
): PrincipalRole {
  if (explicitRole && explicitRole !== "unknown") {
    return explicitRole;
  }

  if (!senderId) {
    return "unknown";
  }

  if (config.principal.ownerIds.includes(senderId)) {
    return "owner";
  }

  if (config.principal.adminIds.includes(senderId)) {
    return "admin";
  }

  return explicitRole ?? "member";
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
    "unknown-conversation"
  );
}

export function resolvePrincipalContext(
  metadata: GuardMetadata,
  config: GuardrailsConfig
): PrincipalResolution {
  const senderId = pickSenderId(metadata);
  const senderHandle =
    asString(metadata.principal?.senderHandle) ??
    asString(metadata.senderHandle) ??
    asString(metadata.username);
  const explicitRole =
    normalizeRole(metadata.principal?.role) ?? normalizeRole(metadata.role);
  const role = inferRole(senderId, explicitRole, config);
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
    senderId: senderId ?? "unknown-sender",
    senderHandle,
    role,
    channelId,
    conversationId: pickConversationId(metadata),
    channelType,
    mentionedAgent,
    pairedDevice
  };

  const hasAnyIdentitySignal =
    Boolean(metadata.principal) ||
    Boolean(asString(metadata.senderId)) ||
    Boolean(asString(metadata.userId)) ||
    Boolean(asString(metadata.fromId));

  return {
    principal,
    missingContext: !hasAnyIdentitySignal
  };
}
