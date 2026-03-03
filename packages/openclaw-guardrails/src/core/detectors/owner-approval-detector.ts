import { REASON_CODES } from "../reason-codes.js";
import type { ApprovalBroker } from "../approval.js";
import type { OwnerApprovalResult } from "./types.js";
import type { ApprovalRequirement, DetectorContext } from "./types.js";

export function detectOwnerApproval(
  context: DetectorContext,
  approvalBroker: ApprovalBroker,
  requirement?: ApprovalRequirement
): OwnerApprovalResult {
  if (!requirement) {
    return { hits: [] };
  }

  const token = context.event.metadata.approval?.token;
  if (!token) {
    return {
      hits: [
        {
          ruleId: "approval.owner.required",
          reasonCode: REASON_CODES.OWNER_APPROVAL_REQUIRED,
          decision: "DENY",
          weight: 0.8
        }
      ],
      approvalChallenge: approvalBroker.createChallenge({
        event: context.event,
        requirement
      })
    };
  }

  const requestId = context.event.metadata.approval?.requestId;
  const verification = approvalBroker.verifyAndConsumeToken(
    token,
    context.event,
    requestId
  );
  if (verification === "valid") {
    return { hits: [] };
  }

  if (verification === "expired") {
    return {
      hits: [
        {
          ruleId: "approval.owner.expired",
          reasonCode: REASON_CODES.OWNER_APPROVAL_EXPIRED,
          decision: "DENY",
          weight: 0.85
        }
      ]
    };
  }

  if (verification === "replayed") {
    return {
      hits: [
        {
          ruleId: "approval.owner.replayed",
          reasonCode: REASON_CODES.OWNER_APPROVAL_REPLAYED,
          decision: "DENY",
          weight: 0.9
        }
      ]
    };
  }

  return {
    hits: [
      {
        ruleId: "approval.owner.invalid",
        reasonCode: REASON_CODES.OWNER_APPROVAL_INVALID,
        decision: "DENY",
        weight: 0.85
      }
    ]
  };
}
