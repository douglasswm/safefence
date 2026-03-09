/**
 * @safefence/types — shared protocol-boundary types
 *
 * Single source of truth for type aliases and constant objects
 * used across control-plane, dashboard, and openclaw-guardrails.
 */

export type InstanceStatus = "registered" | "active" | "connected" | "disconnected" | "deregistered" | "stale";
export type PolicyScope = "org" | "group" | "instance";
export type AuditDecision = "allow" | "deny";

export const INSTANCE_STATUS = {
  REGISTERED: "registered" as const,
  ACTIVE: "active" as const,
  CONNECTED: "connected" as const,
  DISCONNECTED: "disconnected" as const,
  DEREGISTERED: "deregistered" as const,
  STALE: "stale" as const,
};

export const POLICY_SCOPE = {
  ORG: "org" as const,
  GROUP: "group" as const,
  INSTANCE: "instance" as const,
};

export const AUDIT_DECISION = {
  ALLOW: "allow" as const,
  DENY: "deny" as const,
};

export type HeartbeatStatus = "OK" | "POLICY_STALE" | "RBAC_STALE" | "STALE" | "REVOKED";

export const HEARTBEAT_STATUS = {
  OK: "OK" as const,
  POLICY_STALE: "POLICY_STALE" as const,
  RBAC_STALE: "RBAC_STALE" as const,
  STALE: "STALE" as const,
  REVOKED: "REVOKED" as const,
} satisfies Record<HeartbeatStatus, HeartbeatStatus>;
