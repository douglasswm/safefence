import { REASON_CODES } from "../reason-codes.js";
import type { GuardrailsConfig, NormalizedEvent, RuleHit } from "../types.js";

interface CircuitBreakerState {
  failures: number;
  cooldownUntil: number;
}

const circuitBreakers = new Map<string, CircuitBreakerState>();

const CIRCUIT_BREAKER_THRESHOLD = 3;
const CIRCUIT_BREAKER_COOLDOWN_MS = 60_000;

async function validateSingle(
  validator: string,
  event: NormalizedEvent,
  extConfig: NonNullable<GuardrailsConfig["externalValidation"]>
): Promise<RuleHit[]> {
  const cbKey = `${extConfig.endpoint}:${validator}`;
  const cb = circuitBreakers.get(cbKey);
  const now = Date.now();

  if (cb && cb.failures >= CIRCUIT_BREAKER_THRESHOLD && now < cb.cooldownUntil) {
    if (!extConfig.failOpen) {
      return [{
        ruleId: `external_validation_${validator}_circuit_open`,
        reasonCode: REASON_CODES.EXTERNAL_VALIDATION_TIMEOUT,
        decision: "DENY",
        weight: 0.5
      }];
    }
    return [];
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      extConfig.timeoutMs ?? 5000
    );

    const response = await fetch(extConfig.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        validator,
        phase: event.phase,
        content: event.content ?? "",
        toolName: event.toolName,
        agentId: event.agentId
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    circuitBreakers.delete(cbKey);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = (await response.json()) as {
      valid: boolean;
      reason?: string;
    };

    if (!result.valid) {
      return [{
        ruleId: `external_validation_${validator}`,
        reasonCode: REASON_CODES.EXTERNAL_VALIDATION_FAILED,
        decision: "DENY",
        weight: 0.7
      }];
    }

    return [];
  } catch {
    const existing = circuitBreakers.get(cbKey) ?? {
      failures: 0,
      cooldownUntil: 0
    };
    existing.failures += 1;
    existing.cooldownUntil = now + CIRCUIT_BREAKER_COOLDOWN_MS;
    circuitBreakers.set(cbKey, existing);

    if (!extConfig.failOpen) {
      return [{
        ruleId: `external_validation_${validator}_timeout`,
        reasonCode: REASON_CODES.EXTERNAL_VALIDATION_TIMEOUT,
        decision: "DENY",
        weight: 0.5
      }];
    }

    return [];
  }
}

export async function detectExternalValidation(
  event: NormalizedEvent,
  config: GuardrailsConfig
): Promise<RuleHit[]> {
  const extConfig = config.externalValidation;
  if (!extConfig?.enabled) return [];

  const results = await Promise.all(
    extConfig.validators.map((v) => validateSingle(v, event, extConfig))
  );
  return results.flat();
}

/** Reset circuit breaker state (for testing) */
export function resetCircuitBreakers(): void {
  circuitBreakers.clear();
}
