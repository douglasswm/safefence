import { ApprovalBroker } from "./approval.js";
import {
  detectBudget,
  detectCommandPolicy,
  detectInputIntent,
  detectNetworkEgress,
  detectOutputSafety,
  detectOwnerApproval,
  detectPathCanonical,
  detectPrincipalAuthz,
  detectProvenance,
  detectRestrictedInfo,
  detectSensitiveData
} from "./detectors/index.js";
import type { DetectorContext } from "./detectors/types.js";
import { BudgetStore } from "./budget-store.js";
import { unique } from "./event-utils.js";
import { normalizeGuardEvent } from "./normalize.js";
import { REASON_CODES } from "./reason-codes.js";
import { aggregateRisk } from "./scoring.js";
import type {
  Decision,
  GuardDecision,
  GuardEvent,
  GuardrailsConfig,
  RuleHit
} from "./types.js";

function decideFromHits(hits: RuleHit[]): Decision {
  if (hits.some((hit) => hit.decision === "DENY")) {
    return "DENY";
  }

  if (hits.some((hit) => hit.decision === "REDACT")) {
    return "REDACT";
  }

  return "ALLOW";
}

export class GuardrailsEngine {
  private readonly budgetStore: BudgetStore;
  private readonly approvalBroker: ApprovalBroker;

  constructor(
    private readonly config: GuardrailsConfig,
    budgetStore?: BudgetStore,
    approvalBroker?: ApprovalBroker
  ) {
    this.budgetStore = budgetStore ?? new BudgetStore();
    this.approvalBroker = approvalBroker ?? new ApprovalBroker(config);
  }

  approveRequest(
    requestId: string,
    approverId: string,
    approverRole: "owner" | "admin"
  ): string | null {
    return this.approvalBroker.approveRequest(requestId, approverId, approverRole);
  }

  async evaluate(
    rawEvent: Partial<GuardEvent> & Record<string, unknown>,
    fallbackPhase: GuardEvent["phase"] = "message_received"
  ): Promise<GuardDecision> {
    const startedAt = Date.now();

    try {
      const event = normalizeGuardEvent(rawEvent, fallbackPhase);
      const context: DetectorContext = {
        event,
        config: this.config
      };

      const hits: RuleHit[] = [];
      let approvalChallenge: GuardDecision["approvalChallenge"] | undefined;

      hits.push(...detectInputIntent(context));
      hits.push(...detectCommandPolicy(context));
      hits.push(...(await detectPathCanonical(context)));
      hits.push(...(await detectNetworkEgress(context)));
      hits.push(...(await detectProvenance(context)));

      const principalAuthzResult = detectPrincipalAuthz(context);
      hits.push(...principalAuthzResult.hits);
      const ownerApprovalResult = detectOwnerApproval(
        context,
        this.approvalBroker,
        principalAuthzResult.approvalRequirement
      );
      hits.push(...ownerApprovalResult.hits);
      approvalChallenge = ownerApprovalResult.approvalChallenge;

      const sensitiveResult = detectSensitiveData(context);
      hits.push(...sensitiveResult.hits);

      const restrictedInfoResult = detectRestrictedInfo(context);
      hits.push(...restrictedInfoResult.hits);

      const outputResult = detectOutputSafety(
        context,
        restrictedInfoResult.redactedContent ?? sensitiveResult.redactedContent
      );
      hits.push(...outputResult.hits);

      hits.push(...detectBudget(context, this.budgetStore));

      const redactedContent =
        outputResult.redactedContent ??
        restrictedInfoResult.redactedContent ??
        sensitiveResult.redactedContent;
      const enforceDecision = decideFromHits(hits);
      const riskScore = aggregateRisk(hits);
      const elapsedMs = Date.now() - startedAt;

      return this.finalizeDecision(
        enforceDecision,
        hits,
        riskScore,
        redactedContent,
        elapsedMs,
        approvalChallenge
      );
    } catch {
      if (this.config.failClosed) {
        return {
          decision: "DENY",
          reasonCodes: [REASON_CODES.ENGINE_FAILURE],
          riskScore: 1,
          telemetry: {
            matchedRules: ["engine_failure"],
            elapsedMs: Date.now() - startedAt
          }
        };
      }

      return {
        decision: "ALLOW",
        reasonCodes: [REASON_CODES.ENGINE_FAILURE_FAIL_OPEN],
        riskScore: 0,
        telemetry: {
          matchedRules: ["engine_failure_fail_open"],
          elapsedMs: Date.now() - startedAt
        }
      };
    }
  }

  private finalizeDecision(
    enforceDecision: Decision,
    hits: RuleHit[],
    riskScore: number,
    redactedContent: string | undefined,
    elapsedMs: number,
    approvalChallenge?: GuardDecision["approvalChallenge"]
  ): GuardDecision {
    const reasonCodes = unique(hits.map((hit) => hit.reasonCode));
    const matchedRules = unique(hits.map((hit) => hit.ruleId));

    if (this.config.mode === "audit" && enforceDecision !== "ALLOW") {
      const auditReason =
        enforceDecision === "DENY"
          ? REASON_CODES.AUDIT_WOULD_DENY
          : REASON_CODES.AUDIT_WOULD_REDACT;

      return {
        decision: "ALLOW",
        reasonCodes: [auditReason, ...reasonCodes],
        riskScore,
        redactedContent: this.config.redaction.applyInAuditMode
          ? redactedContent
          : undefined,
        approvalChallenge,
        telemetry: {
          matchedRules: [
            `audit_would_${enforceDecision.toLowerCase()}`,
            ...matchedRules
          ],
          elapsedMs
        }
      };
    }

    return {
      decision: enforceDecision,
      reasonCodes,
      riskScore,
      redactedContent,
      approvalChallenge,
      telemetry: {
        matchedRules,
        elapsedMs
      }
    };
  }
}
