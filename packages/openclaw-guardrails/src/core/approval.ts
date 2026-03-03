import crypto from "node:crypto";
import type { ApprovalRequirement } from "./detectors/types.js";
import { ApprovalStore, type ApprovalRecord } from "./approval-store.js";
import type { GuardDecision, GuardrailsConfig, NormalizedEvent, PrincipalRole } from "./types.js";

export type ApprovalVerifyResult = "valid" | "invalid" | "expired" | "replayed";

export interface ApprovalChallengeInput {
  event: NormalizedEvent;
  requirement: ApprovalRequirement;
  nowMs?: number;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  const entries = keys.map((key) => `"${key}":${stableStringify(object[key])}`);
  return `{${entries.join(",")}}`;
}

export function buildApprovalActionDigest(event: NormalizedEvent): string {
  const principal = event.metadata.principal;
  const canonical = stableStringify({
    toolName: event.toolName ?? "",
    args: event.args ?? {},
    dataClass: event.metadata.dataClass ?? "public",
    conversationId: principal?.conversationId ?? "unknown-conversation",
    requesterId: principal?.senderId ?? "unknown-sender"
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

  constructor(
    private readonly config: GuardrailsConfig,
    store?: ApprovalStore
  ) {
    this.store = store ?? new ApprovalStore();
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
    const conversationId = principal?.conversationId ?? "unknown-conversation";
    const requesterId = principal?.senderId ?? "unknown-sender";

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
      return record.token;
    }

    const token = `apr_${crypto.randomUUID().replace(/-/g, "")}`;
    this.store.save({
      ...record,
      approverIds
    });
    this.store.setToken(requestId, token, approverIds.join(","));
    return token;
  }

  verifyAndConsumeToken(
    token: string,
    event: NormalizedEvent,
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

    const principal = event.metadata.principal;
    const requesterId = principal?.senderId ?? "unknown-sender";
    if (record.requesterId !== requesterId) {
      return "invalid";
    }

    if (
      this.config.approval.bindToConversation &&
      record.conversationId !== (principal?.conversationId ?? "unknown-conversation")
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
