import { detectRetrievalTrust } from "../retrieval-trust.js";
import { detectSupplyChainRisk } from "../supply-chain.js";
import type { RuleHit } from "../types.js";
import type { DetectorContext } from "./types.js";

export async function detectProvenance(
  context: DetectorContext
): Promise<RuleHit[]> {
  const hits: RuleHit[] = [];

  hits.push(...(await detectSupplyChainRisk(context.event, context.config)));
  hits.push(...detectRetrievalTrust(context.event, context.config));

  return hits;
}
