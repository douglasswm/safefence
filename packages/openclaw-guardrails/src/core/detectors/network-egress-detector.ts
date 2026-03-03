import {
  extractCommandFromArgs,
  extractUrlCandidatesFromCommand
} from "../command-parse.js";
import { collectNetworkCandidates } from "../event-utils.js";
import {
  containsCommandEgressPattern,
  extractHostFromCandidate,
  isHostAllowlisted,
  isPrivateOrLocalAddress,
  resolveHostAddresses
} from "../network-guard.js";
import { REASON_CODES } from "../reason-codes.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

export async function detectNetworkEgress(context: DetectorContext): Promise<RuleHit[]> {
  const { event, config } = context;
  const hits: RuleHit[] = [];

  if (event.phase !== "before_tool_call") {
    return hits;
  }

  const candidates = collectNetworkCandidates(event.args);
  const command = extractCommandFromArgs(event.args);

  if (command) {
    candidates.push(...extractUrlCandidatesFromCommand(command));

    if (containsCommandEgressPattern(command) && candidates.length === 0) {
      hits.push({
        ruleId: "network.command.unbounded_egress",
        reasonCode: REASON_CODES.NETWORK_HOST_BLOCKED,
        decision: "DENY",
        weight: 0.8
      });
    }
  }

  for (const candidate of candidates) {
    const host = extractHostFromCandidate(candidate);

    if (!host) {
      hits.push({
        ruleId: "network.url.invalid",
        reasonCode: REASON_CODES.INVALID_NETWORK_URL,
        decision: "DENY",
        weight: 0.7
      });
      continue;
    }

    if (isHostAllowlisted(host, config.allow.networkHosts)) {
      continue;
    }

    const resolvedAddresses = await resolveHostAddresses(host);

    if (resolvedAddresses.length === 0) {
      hits.push({
        ruleId: "network.host.invalid",
        reasonCode: REASON_CODES.INVALID_NETWORK_HOST,
        decision: "DENY",
        weight: 0.75
      });
      continue;
    }

    if (!config.allow.allowPrivateEgress) {
      const privateTarget = resolvedAddresses.some((address) =>
        isPrivateOrLocalAddress(address)
      );

      if (privateTarget) {
        hits.push({
          ruleId: "network.private_egress",
          reasonCode: REASON_CODES.NETWORK_PRIVATE_BLOCKED,
          decision: "DENY",
          weight: 0.9
        });
        continue;
      }
    }

    hits.push({
      ruleId: "network.host.allowlist",
      reasonCode: REASON_CODES.NETWORK_HOST_BLOCKED,
      decision: "DENY",
      weight: 0.8
    });
  }

  return hits;
}
