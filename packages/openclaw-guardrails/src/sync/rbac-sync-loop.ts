/**
 * RBACSyncLoop: Receives RBAC change notifications via SSE,
 * pulls deltas from control plane, applies to local SqliteRoleStore.
 */

import type { RoleStore } from "../core/role-store.js";
import { toError } from "../utils/args.js";
import type { ControlPlaneHttpClient } from "./http-client.js";
import type { SyncRoleStore } from "./sync-role-store.js";
import type { RbacSyncResponse, SyncEvent } from "./types.js";

export interface RbacSyncLoopOptions {
  httpClient: ControlPlaneHttpClient;
  roleStore: SyncRoleStore;
  onError?: (error: Error) => void;
}

export class RbacSyncLoop {
  private httpClient: ControlPlaneHttpClient;
  private syncRoleStore: SyncRoleStore;
  private onError?: (error: Error) => void;
  private _rbacVersion = 0;

  constructor(opts: RbacSyncLoopOptions) {
    this.httpClient = opts.httpClient;
    this.syncRoleStore = opts.roleStore;
    this.onError = opts.onError;
  }

  get rbacVersion(): number {
    return this._rbacVersion;
  }

  /** Handle an SSE event. Triggers a pull if rbac_changed or force_resync. */
  async handleEvent(event: SyncEvent): Promise<void> {
    if (event.type !== "rbac_changed" && event.type !== "force_resync") return;
    try {
      await this.pull(event.type === "force_resync");
    } catch (err: unknown) {
      this.onError?.(toError(err));
    }
  }

  /** Pull RBAC state from control plane. Full snapshot if forceFullSync or first pull. */
  async pull(forceFullSync = false): Promise<void> {
    const since = forceFullSync || this._rbacVersion === 0 ? undefined : this._rbacVersion;
    const response: RbacSyncResponse = await this.httpClient.pullRbac(since);
    this.applyRbac(response);
    this._rbacVersion = response.version;
  }

  /** Apply RBAC changes to local RoleStore (bypasses mutation queuing). */
  private applyRbac(response: RbacSyncResponse): void {
    // Use withoutQueuing to prevent echoing cloud data back as local mutations.
    // Wrap in a transaction so all inserts flush as a single disk write.
    this.syncRoleStore.withoutQueuing(() => {
      this.syncRoleStore.runInTransaction(() => {
      // Apply users first (dependency for assignments)
      for (const user of response.users) {
        this.syncRoleStore.ensureUser(user.id, user.displayName);
        for (const identity of user.platformIdentities) {
          this.syncRoleStore.linkPlatformIdentity(identity.platform, identity.platformId, user.id);
        }
      }

      // Apply bots
      for (const bot of response.bots) {
        if (bot.deleted) continue;
        const existing = this.syncRoleStore.getBot(bot.id);
        if (!existing) {
          this.syncRoleStore.ensureUser(bot.ownerId);
          this.syncRoleStore.registerBot(bot.projectId, bot.ownerId, bot.platform, bot.platformBotId ?? bot.id, bot.name);
        }
        if (bot.accessPolicy) {
          this.syncRoleStore.setBotAccessPolicy(bot.id, bot.accessPolicy);
        }
      }

      // Apply roles
      for (const role of response.roles) {
        if (role.deleted) {
          try { this.syncRoleStore.deleteRole(role.id); } catch { /* may not exist */ }
          continue;
        }
        const existing = this.syncRoleStore.getRole(role.id);
        if (!existing) {
          this.syncRoleStore.createRole(role.projectId, role.name, [], role.description, "control-plane");
        }
      }

      // Apply permissions
      for (const perm of response.permissions) {
        if (perm.deleted) {
          try { this.syncRoleStore.revokeRolePermission(perm.roleId, perm.permissionId); } catch { /* ok */ }
        } else {
          this.syncRoleStore.grantRolePermission(perm.roleId, perm.permissionId, perm.effect);
        }
      }

      // Apply assignments
      for (const assignment of response.assignments) {
        if (assignment.deleted) {
          try { this.syncRoleStore.revokeRole(assignment.id); } catch { /* ok */ }
          continue;
        }
        try {
          this.syncRoleStore.assignRole(
            assignment.userId,
            assignment.roleId,
            assignment.scopeType,
            assignment.scopeId,
            assignment.botInstanceId,
            assignment.grantedBy ?? "control-plane",
            assignment.expiresAt,
          );
        } catch {
          // Assignment may already exist (idempotent)
        }
      }
      }); // runInTransaction
    }); // withoutQueuing
  }
}
