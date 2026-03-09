/**
 * PolicySyncLoop: Receives policy change notifications via SSE,
 * pulls deltas from control plane, applies to local config + RoleStore.
 */

import type { RoleStore } from "../core/role-store.js";
import type { GuardrailsConfig } from "../core/types.js";
import { MUTABLE_POLICY_KEYS, MUTABLE_POLICY_FIELD_MAP, setConfigValue, validateFieldValue } from "../core/policy-fields.js";
import { toError } from "../utils/args.js";
import type { ControlPlaneHttpClient } from "./http-client.js";
import type { SyncRoleStore } from "./sync-role-store.js";
import type { PolicySyncResponse, SyncEvent } from "./types.js";

export interface PolicySyncLoopOptions {
  httpClient: ControlPlaneHttpClient;
  roleStore: SyncRoleStore;
  config: GuardrailsConfig;
  onError?: (error: Error) => void;
}

export class PolicySyncLoop {
  private httpClient: ControlPlaneHttpClient;
  private syncRoleStore: SyncRoleStore;
  private config: GuardrailsConfig;
  private onError?: (error: Error) => void;
  private _policyVersion = 0;

  constructor(opts: PolicySyncLoopOptions) {
    this.httpClient = opts.httpClient;
    this.syncRoleStore = opts.roleStore;
    this.config = opts.config;
    this.onError = opts.onError;
  }

  get policyVersion(): number {
    return this._policyVersion;
  }

  /** Handle an SSE event. Triggers a pull if policy_changed or force_resync. */
  async handleEvent(event: SyncEvent): Promise<void> {
    if (event.type !== "policy_changed" && event.type !== "force_resync") return;
    try {
      await this.pull(event.type === "force_resync");
    } catch (err: unknown) {
      this.onError?.(toError(err));
    }
  }

  /** Pull policies from control plane. Full snapshot if forceFullSync or first pull. */
  async pull(forceFullSync = false): Promise<void> {
    const since = forceFullSync || this._policyVersion === 0 ? undefined : this._policyVersion;
    const response: PolicySyncResponse = await this.httpClient.pullPolicies(since);
    this.applyPolicies(response);
    this._policyVersion = response.version;
  }

  /** Apply policies from a sync response to local stores (bypasses mutation queuing). */
  private applyPolicies(response: PolicySyncResponse): void {
    // Use withoutQueuing to prevent echoing cloud data back as local mutations
    this.syncRoleStore.withoutQueuing(() => {
      if (response.isFullSnapshot) {
        const existing = this.syncRoleStore.getAllPolicyOverrides();
        for (const override of existing) {
          this.syncRoleStore.deletePolicyOverride(override.key);
        }
      }

      for (const policy of response.policies) {
        if (!MUTABLE_POLICY_KEYS.has(policy.key)) continue;
        // M2: Validate synced policies before applying
        const fieldDef = MUTABLE_POLICY_FIELD_MAP.get(policy.key);
        if (fieldDef) {
          const validationError = validateFieldValue(fieldDef, policy.value);
          if (validationError) {
            console.warn(`[safefence] Skipping invalid synced policy "${policy.key}": ${validationError}`);
            continue;
          }
        }
        this.syncRoleStore.setPolicyOverride(policy.key, policy.value, policy.updatedBy ?? "control-plane");
        setConfigValue(this.config, policy.key, policy.value);
      }
    });
  }
}
