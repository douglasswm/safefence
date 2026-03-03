import { REASON_CODES } from "./reason-codes.js";
import type { DataClass, GuardrailsConfig, NormalizedEvent, RuleHit } from "./types.js";
import type { ApprovalRequirement } from "./detectors/types.js";

export interface AuthorizationResult {
  hits: RuleHit[];
  approvalRequirement?: ApprovalRequirement;
}

function isOwnerRole(role: string): boolean {
  return role === "owner";
}

function shouldAllowByDefault(config: GuardrailsConfig): boolean {
  return config.authorization.defaultEffect === "allow";
}

function isRestrictedDataClass(
  dataClass: DataClass,
  config: GuardrailsConfig
): boolean {
  return config.authorization.restrictedDataClasses.includes(
    dataClass as Exclude<DataClass, "public">
  );
}

function dataClassNeedsApproval(
  dataClass: DataClass,
  config: GuardrailsConfig
): boolean {
  return (
    dataClass === "restricted" || dataClass === "secret"
      ? config.approval.requireForDataClasses.includes(dataClass)
      : false
  );
}

export function evaluateAuthorization(
  event: NormalizedEvent,
  config: GuardrailsConfig
): AuthorizationResult {
  const hits: RuleHit[] = [];
  const principal = event.metadata.principal;

  if (!principal) {
    return {
      hits: [
        {
          ruleId: "principal.context.missing",
          reasonCode: REASON_CODES.PRINCIPAL_CONTEXT_MISSING,
          decision: "DENY",
          weight: 0.9
        }
      ]
    };
  }

  if (
    config.principal.requireContext &&
    event.metadata.principalMissingContext &&
    principal.channelType === "group"
  ) {
    hits.push({
      ruleId: "principal.context.group_missing",
      reasonCode: REASON_CODES.PRINCIPAL_CONTEXT_MISSING,
      decision: "DENY",
      weight: 0.95
    });
  }

  if (principal.channelType === "group") {
    if (config.principal.failUnknownInGroup && principal.role === "unknown") {
      hits.push({
        ruleId: "principal.group.unknown_sender",
        reasonCode: REASON_CODES.GROUP_SENDER_NOT_ALLOWED,
        decision: "DENY",
        weight: 0.95
      });
    }

    if (
      config.authorization.requireMentionInGroups &&
      principal.mentionedAgent !== true &&
      (event.phase === "message_received" || event.phase === "before_tool_call")
    ) {
      hits.push({
        ruleId: "principal.group.require_mention",
        reasonCode: REASON_CODES.GROUP_SENDER_NOT_ALLOWED,
        decision: "DENY",
        weight: 0.7
      });
    }
  }

  let approvalRequirement: ApprovalRequirement | undefined;

  if (event.phase === "before_tool_call" && event.toolName) {
    const toolName = event.toolName;
    const roleAllowlist = config.authorization.toolAllowByRole[principal.role] ?? [];
    const isRestrictedTool = config.authorization.restrictedTools.includes(toolName);
    const roleAllowsTool = roleAllowlist.includes(toolName);

    if (
      isRestrictedTool &&
      !roleAllowsTool
    ) {
      const needsApproval =
        config.approval.enabled &&
        config.approval.requireForTools.includes(toolName) &&
        principal.channelType === "group" &&
        principal.role !== "owner";

      if (needsApproval) {
        approvalRequirement = {
          reason: `Owner approval required for restricted tool: ${toolName}`,
          requiredRole: "owner"
        };
      } else if (!shouldAllowByDefault(config)) {
        hits.push({
          ruleId: "authorization.role.tool_restricted",
          reasonCode: REASON_CODES.ROLE_TOOL_NOT_ALLOWED,
          decision: "DENY",
          weight: 0.9
        });
      }
    }
  }

  if (event.phase === "before_tool_call") {
    const dataClass = (event.metadata.dataClass ?? "public") as DataClass;
    if (isRestrictedDataClass(dataClass, config) && !isOwnerRole(principal.role)) {
      const needsApproval =
        config.approval.enabled &&
        dataClassNeedsApproval(dataClass, config) &&
        principal.channelType === "group" &&
        principal.role !== "owner";

      if (needsApproval && !approvalRequirement) {
        approvalRequirement = {
          reason: `Owner approval required for ${dataClass} data access`,
          requiredRole: "owner"
        };
      } else if (!needsApproval && !shouldAllowByDefault(config)) {
        hits.push({
          ruleId: "authorization.data_class.restricted",
          reasonCode: REASON_CODES.RESTRICTED_INFO_ROLE_BLOCKED,
          decision: "DENY",
          weight: 0.9
        });
      }
    }
  }

  return {
    hits,
    approvalRequirement
  };
}
