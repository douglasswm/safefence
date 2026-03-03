import { evaluateAuthorization } from "../authorization.js";
import { resolvePrincipalContext } from "../identity.js";
import type { PrincipalAuthzResult } from "./types.js";
import type { DetectorContext } from "./types.js";

export function detectPrincipalAuthz(context: DetectorContext): PrincipalAuthzResult {
  const { event, config } = context;
  const resolution = resolvePrincipalContext(event.metadata, config);

  event.metadata.principal = resolution.principal;
  event.metadata.principalMissingContext = resolution.missingContext;

  const authz = evaluateAuthorization(event, config);
  return {
    hits: authz.hits,
    principal: resolution.principal,
    approvalRequirement: authz.approvalRequirement
  };
}
