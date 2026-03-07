import { ApprovalBroker } from "./approval.js";
import type { AuditEvent, AuditSink } from "./audit-sink.js";
import { NoopAuditSink } from "./audit-sink.js";
import type { NotificationSink } from "./notification-sink.js";
import type { CustomValidator } from "./custom-validator.js";
import {
  detectBudget,
  detectCommandPolicy,
  detectExternalValidation,
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
import type { TokenUsageStore } from "./token-usage-store.js";
import type { RoleStore } from "./role-store.js";
import type {
  ApproverRole,
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

export interface EngineOptions {
  budgetStore?: BudgetStore;
  approvalBroker?: ApprovalBroker;
  auditSink?: AuditSink;
  customValidators?: CustomValidator[];
  tokenUsageStore?: TokenUsageStore;
  notificationSink?: NotificationSink;
  roleStore?: RoleStore;
}

export class GuardrailsEngine {
  private readonly budgetStore: BudgetStore;
  private readonly approvalBroker: ApprovalBroker;
  private readonly auditSink: AuditSink;
  private readonly customValidators: CustomValidator[];
  readonly tokenUsageStore: TokenUsageStore | undefined;
  readonly roleStore: RoleStore | undefined;

  constructor(
    private readonly config: GuardrailsConfig,
    options?: EngineOptions
  ) {
    const opts = options ?? {};
    this.budgetStore = opts.budgetStore ?? new BudgetStore();
    this.approvalBroker = opts.approvalBroker ?? new ApprovalBroker(config, undefined, opts.notificationSink);
    this.auditSink = opts.auditSink ?? new NoopAuditSink();
    this.customValidators = opts.customValidators ?? [];
    this.tokenUsageStore = opts.tokenUsageStore;
    this.roleStore = opts.roleStore;
  }

  approveRequest(
    requestId: string,
    approverId: string,
    approverRole: ApproverRole
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
        config: this.config,
        roleStore: this.roleStore
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

      // External validation + custom validators run concurrently
      const extensionTasks: Promise<RuleHit[]>[] = [];
      extensionTasks.push(detectExternalValidation(event, this.config));
      for (const validator of this.customValidators) {
        if (validator.phases.length === 0 || validator.phases.includes(event.phase)) {
          extensionTasks.push(
            Promise.resolve()
              .then(() => validator.validate({ event, config: this.config }))
              .catch(() => [] as RuleHit[])
          );
        }
      }
      const extensionResults = await Promise.all(extensionTasks);
      for (const result of extensionResults) {
        hits.push(...result);
      }

      const redactedContent =
        outputResult.redactedContent ??
        restrictedInfoResult.redactedContent ??
        sensitiveResult.redactedContent;
      const enforceDecision = decideFromHits(hits);
      const riskScore = aggregateRisk(hits);
      const elapsedMs = Date.now() - startedAt;

      const decision = this.finalizeDecision(
        enforceDecision,
        hits,
        riskScore,
        redactedContent,
        elapsedMs,
        approvalChallenge
      );

      if (this.config.audit.enabled) {
        const auditEvent: AuditEvent = {
          timestamp: new Date(startedAt).toISOString(),
          phase: event.phase,
          agentId: event.agentId,
          senderId: event.metadata.principal?.senderId,
          toolName: event.toolName,
          decision: decision.decision,
          reasonCodes: decision.reasonCodes,
          riskScore: decision.riskScore,
          elapsedMs: decision.telemetry.elapsedMs,
          approvalRequestId: decision.approvalChallenge?.requestId
        };
        this.auditSink.append(auditEvent);
      }

      return decision;
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
