import { REASON_CODES } from "../reason-codes.js";
import type { DataClass } from "../types.js";
import type { DetectorContext, DetectorResult } from "./types.js";

function isOwner(role: string | undefined): boolean {
  return role === "owner";
}

function isRestricted(dataClass: DataClass, restricted: string[]): boolean {
  return restricted.includes(dataClass);
}

export function detectRestrictedInfo(context: DetectorContext): DetectorResult {
  const { event, config } = context;
  const principal = event.metadata.principal;
  const dataClass = (event.metadata.dataClass ?? "public") as DataClass;

  if (!principal || isOwner(principal.role)) {
    return { hits: [] };
  }

  if (!isRestricted(dataClass, config.authorization.restrictedDataClasses)) {
    return { hits: [] };
  }

  if (
    event.phase !== "message_received" &&
    event.phase !== "tool_result_persist" &&
    event.phase !== "message_sending"
  ) {
    return { hits: [] };
  }

  if (!config.tenancy.redactCrossPrincipalOutput) {
    return {
      hits: [
        {
          ruleId: "restricted.info.role_blocked",
          reasonCode: REASON_CODES.RESTRICTED_INFO_ROLE_BLOCKED,
          decision: "DENY",
          weight: 0.9
        }
      ]
    };
  }

  const base = config.redaction.replacement;
  const replacement = base.endsWith("]")
    ? `${base.slice(0, -1)}:${dataClass.toUpperCase()}]`
    : `${base}:${dataClass.toUpperCase()}`;
  const redactedContent = event.content ? replacement : undefined;

  return {
    hits: [
      {
        ruleId: "restricted.info.redacted",
        reasonCode: REASON_CODES.RESTRICTED_INFO_ROLE_BLOCKED,
        decision: "REDACT",
        weight: 0.7
      }
    ],
    redactedContent
  };
}
