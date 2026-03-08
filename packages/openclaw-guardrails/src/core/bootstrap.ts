/**
 * First-owner bootstrap: shared logic for /sf setup, CLI setup, and HTTP setup.
 *
 * All three surfaces delegate here so the bootstrap sequence is defined once.
 */

import { parseSenderId } from "./identity.js";
import type { RoleStore } from "./role-store.js";
import { AUDIT_EVENT_TYPES } from "./types.js";

export interface BootstrapResult {
  success: boolean;
  error?: string;
  ownerId?: string;
  projectId?: string;
}

const DEFAULT_ORG_ID = "default-org";
const DEFAULT_PROJECT_ID = "default-project";
const DEFAULT_PROJECT_NAME = "Default Project";

/**
 * Claim first-owner on a fresh install.
 *
 * - Checks `hasAnySuperadmin()` — rejects if an owner already exists.
 * - Creates the default org + project (idempotent).
 * - Registers the sender as a user + links platform identity.
 * - Assigns the `superadmin` system role.
 * - Audit-logs the bootstrap event.
 *
 * On SqliteRoleStore this runs inside a transaction to prevent TOCTOU races
 * where two concurrent callers both pass the check.
 */
export function bootstrapFirstOwner(
  store: RoleStore,
  senderId: string,
  source?: string
): BootstrapResult {
  // SqliteRoleStore wraps this in db.transaction(); ConfigRoleStore throws.
  return store.bootstrapOwner(senderId, source);
}

/**
 * Core bootstrap logic extracted for use by SqliteRoleStore's transactional wrapper.
 * Not meant to be called directly — use `bootstrapFirstOwner()` or `store.bootstrapOwner()`.
 */
export function executeBootstrap(
  store: RoleStore,
  senderId: string,
  source?: string
): BootstrapResult {
  if (store.hasAnySuperadmin()) {
    return { success: false, error: "Setup already completed. An owner already exists." };
  }

  const projectId = DEFAULT_PROJECT_ID;

  try {
    store.ensureProject(projectId, DEFAULT_ORG_ID, DEFAULT_PROJECT_NAME);
  } catch {
    // may already exist
  }

  const parsed = parseSenderId(senderId);

  store.ensureUser(senderId, undefined);
  if (parsed) {
    store.linkPlatformIdentity(parsed.platform, parsed.platformId, senderId);
  }

  const roles = store.listRoles(projectId);
  const superadminRole = roles.find((r) => r.name === "superadmin" && r.isSystem);
  if (!superadminRole) {
    return { success: false, error: "superadmin role not found. RBAC store may not be initialized." };
  }

  store.assignRole(senderId, superadminRole.id, "project", projectId, undefined, "system");

  store.logDecision({
    eventType: AUDIT_EVENT_TYPES.SETUP_BOOTSTRAP,
    actorUserId: senderId,
    actorPlatform: parsed?.platform,
    actorPlatformId: parsed?.platformId,
    projectId,
    details: { action: "first_owner_claim", source: source ?? "unknown" }
  });

  return { success: true, ownerId: senderId, projectId };
}
