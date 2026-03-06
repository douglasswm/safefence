import crypto from "node:crypto";
import type { ApprovalRequirement } from "./detectors/types.js";
import { ApprovalStore, type ApprovalRecord } from "./approval-store.js";
import { UNKNOWN_SENDER, UNKNOWN_CONVERSATION } from "./identity.js";
import type { NotificationSink } from "./notification-sink.js";
import type { GuardDecision, GuardrailsConfig, NormalizedEvent, PrincipalRole } from "./types.js";

export type ApprovalVerifyResult = "valid" | "invalid" | "expired" | "replayed";

export interface ApprovalChallengeInput {
  event: NormalizedEvent;
  requirement: ApprovalRequirement;
  nowMs?: number;
}

function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(v).sort()) {
        sorted[k] = (v as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return v;
  });
}

export function buildApprovalActionDigest(event: NormalizedEvent): string {
  const principal = event.metadata.principal;
  const canonical = stableStringify({
    toolName: event.toolName ?? "",
    args: event.args ?? {},
    dataClass: event.metadata.dataClass ?? "public",
    conversationId: principal?.conversationId ?? UNKNOWN_CONVERSATION,
    requesterId: principal?.senderId ?? UNKNOWN_SENDER
  });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

function canRoleApprove(requiredRole: "owner" | "admin", approverRole: PrincipalRole): boolean {
  if (requiredRole === "owner") {
    return approverRole === "owner";
  }
  return approverRole === "owner" || approverRole === "admin";
}

export class ApprovalBroker {
  private readonly store: ApprovalStore;
  private readonly notificationSink: NotificationSink | undefined;

  constructor(
    private readonly config: GuardrailsConfig,
    store?: ApprovalStore,
    notificationSink?: NotificationSink
  ) {
    this.store = store ?? new ApprovalStore(config.approval.storagePath, config.workspaceRoot);
    this.notificationSink = notificationSink;
  }

  createChallenge({
    event,
    requirement,
    nowMs = Date.now()
  }: ApprovalChallengeInput): GuardDecision["approvalChallenge"] {
    const principal = event.metadata.principal;
    const requestId = crypto.randomUUID();
    const expiresAt = nowMs + this.config.approval.ttlSeconds * 1_000;
    const actionDigest = buildApprovalActionDigest(event);
    const conversationId = principal?.conversationId ?? UNKNOWN_CONVERSATION;
    const requesterId = principal?.senderId ?? UNKNOWN_SENDER;

    const record: ApprovalRecord = {
      requestId,
      actionDigest,
      requesterId,
      conversationId,
      requiredRole: requirement.requiredRole,
      reason: requirement.reason,
      createdAt: nowMs,
      expiresAt,
      approverIds: []
    };

    this.store.save(record);

    if (this.notificationSink && this.config.notifications.enabled) {
      try {
        void this.notificationSink.notify({
          requestId,
          requesterId,
          toolName: event.toolName,
          reason: requirement.reason,
          requiredRole: requirement.requiredRole,
          expiresAt,
          conversationId
        });
      } catch {
        // Notification failures must not break the approval flow
      }
    }

    return {
      requestId,
      expiresAt,
      reason: requirement.reason,
      requiredRole: requirement.requiredRole
    };
  }

  approveRequest(
    requestId: string,
    approverId: string,
    approverRole: PrincipalRole,
    nowMs = Date.now()
  ): string | null {
    const record = this.store.getByRequestId(requestId);
    if (!record) {
      return null;
    }

    if (record.expiresAt <= nowMs) {
      return null;
    }

    if (!canRoleApprove(record.requiredRole, approverRole)) {
      return null;
    }

    if (record.requesterId === approverId) {
      return null;
    }

    const hasApproved = record.approverIds.includes(approverId);
    const approverIds = hasApproved
      ? record.approverIds
      : [...record.approverIds, approverId];
    const quorum = Math.max(1, this.config.approval.ownerQuorum);

    if (approverIds.length < quorum) {
      this.store.save({
        ...record,
        approverIds
      });
      return null;
    }

    if (record.token) {
      return record.usedAt ? null : record.token;
    }

    const token = `apr_${crypto.randomUUID().replace(/-/g, "")}`;
    this.store.setToken(requestId, token, approverIds.join(","));
    return token;
  }

  verifyAndConsumeToken(
    token: string,
    event: NormalizedEvent,
    requestId?: string,
    nowMs = Date.now()
  ): ApprovalVerifyResult {
    const record = this.store.getByToken(token);
    if (!record) {
      return "invalid";
    }

    if (record.expiresAt <= nowMs) {
      return "expired";
    }

    if (record.usedAt) {
      return "replayed";
    }

    if (requestId && record.requestId !== requestId) {
      return "invalid";
    }

    const principal = event.metadata.principal;
    const requesterId = principal?.senderId ?? UNKNOWN_SENDER;
    if (record.requesterId !== requesterId) {
      return "invalid";
    }

    if (
      this.config.approval.bindToConversation &&
      record.conversationId !== (principal?.conversationId ?? UNKNOWN_CONVERSATION)
    ) {
      return "invalid";
    }

    const digest = buildApprovalActionDigest(event);
    if (record.actionDigest !== digest) {
      return "invalid";
    }

    this.store.markUsed(record.requestId, nowMs);
    return "valid";
  }
}
