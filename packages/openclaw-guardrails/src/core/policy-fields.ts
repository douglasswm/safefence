/**
 * Policy field registry: defines which GuardrailsConfig fields are mutable
 * at runtime via /sf policy, HTTP admin API, and CLI.
 *
 * Fields NOT listed here are static security invariants that require
 * a config file change + gateway restart.
 */

import type { GuardrailsConfig } from "./types.js";
import type { RoleStore } from "./role-store.js";

export interface PolicyFieldDef {
  key: string;
  type: "string" | "number" | "boolean" | "string[]" | "json";
  description: string;
  validate?: (value: unknown) => string | null;
}

const validModes = new Set(["enforce", "audit"]);
const validStages = new Set(["stage_a_audit", "stage_b_high_risk_enforce", "stage_c_full_enforce"]);

function positiveNumber(v: unknown): string | null {
  return typeof v === "number" && v > 0 ? null : "must be a positive number";
}

function nonNegativeNumber(v: unknown): string | null {
  return typeof v === "number" && v >= 0 ? null : "must be a non-negative number";
}

export const MUTABLE_POLICY_FIELDS: PolicyFieldDef[] = [
  // Operating mode
  { key: "mode", type: "string", description: "Enforcement mode (enforce | audit)", validate: (v) => validModes.has(v as string) ? null : "must be 'enforce' or 'audit'" },
  { key: "rollout.stage", type: "string", description: "Rollout stage", validate: (v) => validStages.has(v as string) ? null : "must be stage_a_audit, stage_b_high_risk_enforce, or stage_c_full_enforce" },
  { key: "rollout.highRiskTools", type: "string[]", description: "Tools enforced in stage_b" },

  // Rate limits
  { key: "limits.maxRequestsPerMinute", type: "number", description: "Max requests per minute", validate: positiveNumber },
  { key: "limits.maxToolCallsPerMinute", type: "number", description: "Max tool calls per minute", validate: positiveNumber },
  { key: "limits.maxInputChars", type: "number", description: "Max input characters", validate: positiveNumber },
  { key: "limits.maxToolArgChars", type: "number", description: "Max tool argument characters", validate: positiveNumber },
  { key: "limits.maxOutputChars", type: "number", description: "Max output characters", validate: positiveNumber },

  // Tool policy
  { key: "allow.tools", type: "string[]", description: "Allowed tool names" },
  { key: "allow.networkHosts", type: "string[]", description: "Allowed network hosts" },
  { key: "authorization.restrictedTools", type: "string[]", description: "Tools requiring elevated access" },
  { key: "authorization.requireMentionInGroups", type: "boolean", description: "Require @mention in group chats" },
  { key: "authorization.toolAllowByRole", type: "json", description: "Per-role tool allowlists (JSON object)" },

  // Approval
  { key: "approval.enabled", type: "boolean", description: "Enable owner-approval workflow" },
  { key: "approval.ttlSeconds", type: "number", description: "Approval token TTL in seconds", validate: positiveNumber },
  { key: "approval.requireForTools", type: "string[]", description: "Tools that require approval" },

  // Monitoring
  { key: "monitoring.falsePositiveThresholdPct", type: "number", description: "False positive threshold %", validate: nonNegativeNumber },
  { key: "monitoring.consecutiveDaysForTuning", type: "number", description: "Consecutive days for tuning trigger", validate: positiveNumber },

  // Notifications
  { key: "notifications.enabled", type: "boolean", description: "Enable admin notifications" },
  { key: "notifications.adminChannelId", type: "string", description: "Admin notification channel ID" },

  // Supply chain
  { key: "supplyChain.allowedSkillHashes", type: "string[]", description: "Approved skill hashes" },
  { key: "supplyChain.trustedSkillSources", type: "string[]", description: "Trusted skill source URLs" },
];

export const MUTABLE_POLICY_KEYS = new Set(MUTABLE_POLICY_FIELDS.map((f) => f.key));
export const MUTABLE_POLICY_FIELD_MAP = new Map(MUTABLE_POLICY_FIELDS.map((f) => [f.key, f]));

export function getConfigValue(config: GuardrailsConfig, dotPath: string): unknown {
  const parts = dotPath.split(".");
  let current: unknown = config;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function setConfigValue(config: GuardrailsConfig, dotPath: string, value: unknown): void {
  const parts = dotPath.split(".");
  let current: Record<string, unknown> = config as unknown as Record<string, unknown>;
  for (let i = 0; i < parts.length - 1; i++) {
    const next = current[parts[i]];
    if (next == null || typeof next !== "object") return;
    current = next as Record<string, unknown>;
  }
  current[parts[parts.length - 1]] = value;
}

/**
 * Parse a string value into the correct type for a policy field.
 */
export function parseFieldValue(field: PolicyFieldDef, raw: string): unknown {
  switch (field.type) {
    case "number": {
      const n = Number(raw);
      if (Number.isNaN(n)) throw new Error(`Invalid number: ${raw}`);
      return n;
    }
    case "boolean": {
      if (raw === "true") return true;
      if (raw === "false") return false;
      throw new Error(`Invalid boolean: ${raw} (use 'true' or 'false')`);
    }
    case "string":
      return raw;
    case "string[]": {
      // Accept JSON array or comma-separated
      if (raw.startsWith("[")) return JSON.parse(raw) as string[];
      return raw.split(",").map((s) => s.trim()).filter(Boolean);
    }
    case "json":
      return JSON.parse(raw) as unknown;
    default:
      return raw;
  }
}

/**
 * Validate a value for a specific policy field.
 * Returns error message or null if valid.
 */
export function validateFieldValue(field: PolicyFieldDef, value: unknown): string | null {
  // Type checks
  switch (field.type) {
    case "number":
      if (typeof value !== "number") return `expected number, got ${typeof value}`;
      break;
    case "boolean":
      if (typeof value !== "boolean") return `expected boolean, got ${typeof value}`;
      break;
    case "string":
      if (typeof value !== "string") return `expected string, got ${typeof value}`;
      break;
    case "string[]":
      if (!Array.isArray(value) || !value.every((v) => typeof v === "string"))
        return "expected string array";
      break;
    case "json":
      if (value == null || typeof value !== "object") return "expected JSON object";
      break;
  }

  // Custom validation
  if (field.validate) return field.validate(value);
  return null;
}

// Module-level snapshot of pre-override defaults for reset support.
let _defaults: Map<string, unknown> | undefined;

/**
 * Snapshot current values of all mutable fields for reset support.
 * Call this BEFORE applying overrides. Captured internally.
 */
export function snapshotMutableDefaults(config: GuardrailsConfig): void {
  _defaults = new Map<string, unknown>();
  for (const field of MUTABLE_POLICY_FIELDS) {
    const value = getConfigValue(config, field.key);
    // Deep-copy arrays/objects so mutations don't affect the snapshot
    _defaults.set(field.key, value != null && typeof value === "object" ? JSON.parse(JSON.stringify(value)) : value);
  }
}

/**
 * Get the pre-override default value for a mutable policy field.
 */
export function getMutableDefault(key: string): unknown {
  return _defaults?.get(key);
}

/**
 * Load all persisted policy overrides from the store and apply them
 * to the config object in-place.
 */
export function applyPolicyOverrides(config: GuardrailsConfig, store: RoleStore): void {
  const overrides = store.getAllPolicyOverrides();
  for (const { key, value } of overrides) {
    if (!MUTABLE_POLICY_KEYS.has(key)) continue;
    setConfigValue(config, key, value);
  }
}
