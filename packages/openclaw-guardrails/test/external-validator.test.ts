import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { detectExternalValidation, resetCircuitBreakers } from "../src/core/detectors/external-validator-detector.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";
import type { GuardrailsConfig, NormalizedEvent } from "../src/core/types.js";

function makeEvent(overrides: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    phase: "message_received",
    agentId: "agent-1",
    content: "test content",
    args: {},
    metadata: {},
    ...overrides
  };
}

function makeConfig(extOverrides: Partial<NonNullable<GuardrailsConfig["externalValidation"]>> = {}): GuardrailsConfig {
  const base = createDefaultConfig("/workspace");
  return {
    ...base,
    externalValidation: {
      enabled: true,
      endpoint: "https://guard.example.com/validate",
      timeoutMs: 3000,
      validators: ["jailbreak"],
      failOpen: false,
      ...extOverrides
    }
  };
}

describe("detectExternalValidation", () => {
  beforeEach(() => {
    resetCircuitBreakers();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns empty hits when disabled", async () => {
    const config = createDefaultConfig("/workspace");
    const hits = await detectExternalValidation(makeEvent(), config);
    expect(hits).toHaveLength(0);
  });

  it("returns empty hits when validator passes", async () => {
    const config = makeConfig();
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ valid: true }), { status: 200 })
    );

    const hits = await detectExternalValidation(makeEvent(), config);
    expect(hits).toHaveLength(0);
  });

  it("returns EXTERNAL_VALIDATION_FAILED when validator rejects", async () => {
    const config = makeConfig();
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ valid: false, reason: "jailbreak detected" }), { status: 200 })
    );

    const hits = await detectExternalValidation(makeEvent(), config);
    expect(hits).toHaveLength(1);
    expect(hits[0].reasonCode).toBe(REASON_CODES.EXTERNAL_VALIDATION_FAILED);
  });

  it("returns EXTERNAL_VALIDATION_TIMEOUT on fetch error (failOpen=false)", async () => {
    const config = makeConfig({ failOpen: false });
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("network error"));

    const hits = await detectExternalValidation(makeEvent(), config);
    expect(hits).toHaveLength(1);
    expect(hits[0].reasonCode).toBe(REASON_CODES.EXTERNAL_VALIDATION_TIMEOUT);
  });

  it("returns empty hits on fetch error when failOpen=true", async () => {
    const config = makeConfig({ failOpen: true });
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("network error"));

    const hits = await detectExternalValidation(makeEvent(), config);
    expect(hits).toHaveLength(0);
  });

  it("opens circuit breaker after 3 consecutive failures", async () => {
    const config = makeConfig({ failOpen: false });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("fail"));

    // Trip the breaker (3 failures)
    await detectExternalValidation(makeEvent(), config);
    await detectExternalValidation(makeEvent(), config);
    await detectExternalValidation(makeEvent(), config);

    expect(fetchSpy).toHaveBeenCalledTimes(3);

    // 4th call should not invoke fetch (circuit open)
    const hits = await detectExternalValidation(makeEvent(), config);
    expect(fetchSpy).toHaveBeenCalledTimes(3); // still 3
    expect(hits).toHaveLength(1);
    expect(hits[0].reasonCode).toBe(REASON_CODES.EXTERNAL_VALIDATION_TIMEOUT);
  });
});
