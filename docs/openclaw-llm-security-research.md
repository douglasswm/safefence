# OpenClaw Security Research: OWASP LLM Top 10 and Active Exploitation

Date: March 3, 2026

## Executive Summary

This report analyzes OpenClaw risk exposure against OWASP Top 10 for LLM Applications (2025), documents disclosed OpenClaw vulnerability classes, and provides a concrete hardening strategy.

Key findings:

1. OpenClaw had multiple high-impact security advisories from January to February 2026, including gateway override abuse, skill install path escape, symlink boundary bypass, and privilege-escalation classes.
2. Exploitation is currently practical where deployments are unpatched or weakly configured. Publicly described attack chains and PoCs indicate adversaries can reproduce these paths with low-to-moderate effort.
3. The most important controls are patch currency (`>=2026.2.25`), strict tool/network/path guardrails, least privilege, and deterministic pre-tool enforcement.
4. A native local guardrails plugin is the most robust architecture for OpenClaw: single decision kernel, declarative policy, fail-closed enforcement, and no dependency on remote inference services.

## Threat Intelligence Snapshot (March 3, 2026)

| Vulnerability / Class | Source | Affected Window | Patch | Exploit Practicality | Confidence |
|---|---|---|---|---|---|
| 1-click RCE via gateway URL/token leakage (GHSA-g8p2-7wf7-98mq) | OpenClaw GHSA | `< 2026.1.29` | `2026.1.29` | High (publicly described chain, direct abuse path) | High |
| Gateway URL override abuse / SSRF-like pivot (CVE-2026-26322, GHSA-g6q9-8fvw-f7rf) | OpenClaw GHSA, NVD | `< 2026.2.14` | `2026.2.14` | High (straightforward crafted parameter abuse) | High |
| Skill install target directory escape (CVE-2026-27008, GHSA-h7f7-89mm-pqh6) | OpenClaw GHSA, NVD | `< 2026.2.15` | `2026.2.15` | Medium-High (requires privileged path but realistic in misconfigured installs) | High |
| Unpaired device identity privilege escalation (GHSA-553v-f69r-656j) | OpenClaw GHSA | `< 2026.2.25` | `2026.2.25` | High in exposed localhost/browser attack scenarios | Medium-High |
| Agents.files symlink boundary bypass (GHSA-fgvx-58p6-gjwc) | OpenClaw GHSA | `< 2026.2.25` | `2026.2.25` | High (path policy bypass class is broadly reusable) | High |
| IPv6 multicast SSRF classifier bypass (GHSA-h97f-6pqj-q452) | OpenClaw GHSA | `< 2026.2.25` | `2026.2.25` | Medium (depends on network architecture) | High |

Interpretation note: "currently exploited" in this report means public exploitability and reproducibility are established. It does not claim confirmed global mass exploitation telemetry.

## OpenClaw Vulnerability Timeline and Exploit Mechanics

### January 31, 2026: GHSA-g8p2-7wf7-98mq

Class: gateway URL manipulation leading to token leakage and remote code execution pathing.

How it is exploited:

1. Attacker influences a gateway URL input path.
2. Sensitive auth/token material can be pushed to attacker-controlled endpoint.
3. Compromised context is then used to execute privileged actions.

Primary mitigation:

- Patch to `2026.1.29+`.
- Deny untrusted gateway URL overrides entirely.
- Enforce local host allowlist for gateway/tool network destinations.

### February 15, 2026: CVE-2026-26322 (GHSA-g6q9-8fvw-f7rf)

Class: unrestricted gateway URL override (`gatewayUrl`) enabling SSRF-like routing and policy bypass.

How it is exploited:

1. Malicious actor sets `gatewayUrl` to attacker endpoint.
2. Agent traffic is relayed through untrusted infrastructure.
3. Requests/credentials/context can be observed or manipulated.

Primary mitigation:

- Patch to `2026.2.14+`.
- Enforce network host allowlist.
- Reject dynamic gateway destination changes at tool-call time.

### February 18, 2026: CVE-2026-27008 (GHSA-h7f7-89mm-pqh6)

Class: `skills.install` `targetDir` validation weakness (path traversal / arbitrary write boundary break).

How it is exploited:

1. Attacker provides crafted `targetDir` with traversal sequences.
2. Files are written outside intended skill directory boundaries.
3. This can produce persistence or overwrite abuse.

Primary mitigation:

- Patch to `2026.2.15+`.
- Canonicalize and enforce write roots.
- Block `..` and absolute path escapes in all install/write flows.

### February 26, 2026: GHSA-553v-f69r-656j

Class: unpaired device identity privilege escalation.

How it is exploited:

1. Browser/localhost interaction sequence forces or hijacks device registration identity.
2. Untrusted origin gains effective privileged control path.
3. Full account/session takeover can follow depending on deployment posture.

Primary mitigation:

- Patch to `2026.2.25+`.
- Enforce strict device pairing authentication.
- Keep localhost services inaccessible from untrusted browser contexts.

Inference note: External reports describing "ClawJacked" account takeover behavior align with this advisory class and patch window, but exact naming differs by source.

### February 26, 2026: GHSA-fgvx-58p6-gjwc

Class: symlink path escape in `agents.files`.

How it is exploited:

1. Attacker supplies path that appears in-bounds pre-resolution.
2. Symlink or path canonicalization behavior escapes workspace boundary.
3. Sensitive files become readable/writable.

Primary mitigation:

- Patch to `2026.2.25+`.
- Resolve real path before authorization.
- Enforce post-resolution boundary checks.

### February 26, 2026: GHSA-h97f-6pqj-q452

Class: IPv6 multicast SSRF classifier bypass.

How it is exploited:

1. Network validation allows an address pattern believed safe.
2. Traffic reaches internal/unexpected network targets.
3. Internal metadata or services can be queried.

Primary mitigation:

- Patch to `2026.2.25+`.
- Harden SSRF filters for IPv4/IPv6, DNS rebinding, and alternate encodings.
- Default-deny all outbound targets except explicit allowlist.

## OWASP LLM Top 10 (2025) Mapping to OpenClaw

| OWASP LLM Risk | OpenClaw Exposure Pattern | Practical Mitigation |
|---|---|---|
| LLM01 Prompt Injection | Untrusted content manipulates tool-use instructions | Detect injection patterns, immutable policy prompt, pre-tool authorization gate |
| LLM02 Sensitive Disclosure | Token leakage in tool outputs/logs/transit | Output redaction, secret scanning, token minimization, log hygiene |
| LLM03 Supply Chain | Skill/plugin install path abuse and untrusted artifacts | Trusted source policy, integrity checks, bounded install directories |
| LLM04 Data/Model Poisoning | Poisoned retrieved text drives harmful behavior | Source trust scoring, retrieval guardrails, high-risk source quarantine |
| LLM05 Improper Output Handling | Tool/model output reused without sanitization | Treat all outputs as untrusted input, sanitize/validate before execution |
| LLM06 Excessive Agency | Broad tool permissions and unconstrained command execution | Tool allowlist, strict command binary/arg allowlist, human approval for destructive actions |
| LLM07 System Prompt Leakage | Prompt extraction requests via user/retrieved content | Leak pattern deny rules, no prompt echoing, redaction |
| LLM08 Vector/Embedding Weaknesses | Retrieval layer can surface malicious instructions | Retrieval filtering, metadata constraints, signed corpora |
| LLM09 Misinformation | LLM-generated incorrect security recommendations | Source grounding, confidence scoring, policy-bound automation |
| LLM10 Unbounded Consumption | Oversized payload/tool arg abuse causing resource exhaustion | Input/output limits, rate limits, bounded retries/timeouts |

## "Currently Exploited" Status by Confidence

### High Confidence

- Gateway destination override abuse (`gatewayUrl`) and related relay/token exposure patterns.
- Traversal/write-boundary exploitability in skill install flows before patched releases.
- Symlink/path boundary bypass classes before Feb 25 fixes.

### Medium-High Confidence

- Unpaired device registration privilege escalation in browser-to-localhost contexts, based on converging advisory details and external disclosures.

### Medium Confidence

- IPv6 SSRF classifier bypass impact level, which depends on network topology and internal reachable targets.

## Hardening Baseline for OpenClaw

Minimum baseline for production:

1. Upgrade OpenClaw to `>=2026.2.25`.
2. Run `openclaw security audit --deep` and fail deployment on critical findings.
3. Enforce gateway/device auth; disallow permissive pairing shortcuts.
4. Keep sensitive logging redaction enabled and verified.
5. Use tool allowlist + strict command binary/arg allowlist.
6. Restrict write/read paths to workspace roots with canonical path checks.
7. Deny outbound network access by default; allowlist only required hosts.
8. Disable dangerous bypass flags in production configuration.
9. Sandbox tools where possible, but treat sandbox as defense-in-depth, not sole control.
10. Add continuous regression tests for each published advisory class.

## Baseline Gap Closure Status (Guardrails v2)

| Gap | Baseline Risk | v2 Status | Implementation |
|---|---|---|---|
| Lexical path checks only | Symlink/workspace escape bypass | Closed | `src/core/path-canonical.ts`, `detectors/path-canonical-detector.ts` |
| Command prefix allowlist | `&&`/`|` command chaining bypass | Closed | `src/core/command-parse.ts`, `detectors/command-policy-detector.ts` |
| Args-only network checks | Hidden command egress not covered | Closed | `src/core/network-guard.ts`, `detectors/network-egress-detector.ts` |
| Partial supply-chain controls | Untrusted skill source/hash bypass | Closed | `src/core/supply-chain.ts`, `detectors/provenance-detector.ts` |
| Audit mode leakage | Audit allowed unredacted sensitive data | Closed | `src/core/engine.ts`, `src/plugin/openclaw-adapter.ts` |
| Missing budget controls | Unbounded request/tool consumption | Closed | `src/core/budget-store.ts`, `detectors/budget-detector.ts` |
| Missing retrieval trust gates | Retrieval poisoning can trigger tools | Closed | `src/core/retrieval-trust.ts`, `detectors/provenance-detector.ts` |
| OWASP LLM04/08/09 not implemented | Trust and provenance blind spots | Closed (local policy layer) | `retrievalTrust` config + provenance detector |

## Secure-by-Default Config Template (for this plugin)

```json
{
  "mode": "enforce",
  "failClosed": true,
  "workspaceRoot": "/workspace/project",
  "allow": {
    "tools": ["read", "write", "edit", "exec", "process", "apply_patch", "skills.install"],
    "commands": [
      { "binary": "ls" },
      { "binary": "cat" },
      { "binary": "rg" },
      { "binary": "find" },
      { "binary": "pwd" },
      { "binary": "git", "argPattern": "^(status|diff)(\\s+.*)?$" }
    ],
    "writablePaths": ["/workspace/project"],
    "networkHosts": ["localhost", "127.0.0.1", "::1"],
    "allowPrivateEgress": false
  },
  "deny": {
    "commandPatterns": ["\\brm\\s+-rf\\b", "\\bdd\\s+if=", "\\bcurl\\b.{0,40}\\|\\s*(sh|bash)"],
    "pathPatterns": ["\\.\\./", "\\.\\.\\\\", "^/etc/", "^/proc/", "id_rsa", "\\.env"],
    "promptInjectionPatterns": ["ignore.*instructions", "reveal.*system prompt", "bypass.*guardrails"],
    "exfiltrationPatterns": ["exfiltrat", "send.*token", "copy.*credentials"],
    "shellOperatorPatterns": ["&&", "\\|\\|", ";", "(?<!\\|)\\|(?!\\|)", "\\$\\(", "`", ">", "<", "\\n"]
  },
  "redaction": {
    "secretPatterns": ["AKIA[0-9A-Z]{16}", "Bearer\\s+[A-Za-z0-9._-]{16,}", "-----BEGIN(?: RSA)? PRIVATE KEY-----"],
    "piiPatterns": ["[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", "\\b\\d{3}-\\d{2}-\\d{4}\\b"],
    "replacement": "[REDACTED]",
    "applyInAuditMode": true
  },
  "limits": {
    "maxInputChars": 20000,
    "maxToolArgChars": 10000,
    "maxOutputChars": 50000,
    "maxRequestsPerMinute": 120,
    "maxToolCallsPerMinute": 60
  },
  "pathPolicy": {
    "enforceCanonicalRealpath": true,
    "denySymlinkTraversal": true
  },
  "supplyChain": {
    "trustedSkillSources": ["https://github.com/openclaw/"],
    "requireSkillHash": true,
    "allowedSkillHashes": []
  },
  "retrievalTrust": {
    "requiredForToolExecution": true,
    "minimumTrustLevel": "medium",
    "requireSignedSource": false
  }
}
```

## Incident Response Playbook (OpenClaw-Specific)

1. Contain
- Rotate gateway/API/session tokens immediately.
- Disable affected tools and block outbound egress.
- Isolate vulnerable agent runtimes.

2. Eradicate
- Patch to fixed version.
- Remove unauthorized skills/plugins and inspect install paths.
- Rebuild from known-good image/state.

3. Recover
- Re-enable only allowlisted tools/hosts.
- Run regression suite for known advisory classes.
- Monitor for repeated exploit signatures in logs.

4. Lessons Learned
- Add new deny/redaction patterns for observed payloads.
- Add permanent tests reproducing the incident chain.

## Primary References

- OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
- OWASP LLM risk pages: https://genai.owasp.org/llmrisk/
- OpenClaw advisories list: https://github.com/openclaw/openclaw/security/advisories
- GHSA-g8p2-7wf7-98mq: https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq
- GHSA-g6q9-8fvw-f7rf (CVE-2026-26322): https://github.com/openclaw/openclaw/security/advisories/GHSA-g6q9-8fvw-f7rf
- GHSA-h7f7-89mm-pqh6 (CVE-2026-27008): https://github.com/openclaw/openclaw/security/advisories/GHSA-h7f7-89mm-pqh6
- GHSA-553v-f69r-656j: https://github.com/openclaw/openclaw/security/advisories/GHSA-553v-f69r-656j
- GHSA-fgvx-58p6-gjwc: https://github.com/openclaw/openclaw/security/advisories/GHSA-fgvx-58p6-gjwc
- GHSA-h97f-6pqj-q452: https://github.com/openclaw/openclaw/security/advisories/GHSA-h97f-6pqj-q452
- NVD CVE-2026-26322: https://nvd.nist.gov/vuln/detail/CVE-2026-26322
- NVD CVE-2026-27008: https://nvd.nist.gov/vuln/detail/CVE-2026-27008
- OpenClaw docs (agent loop/hardening/sandbox): https://docs.openclaw.ai/
- Knostic openclaw-shield (reference): https://github.com/knostic/openclaw-shield
- Guardrails AI (reference only): https://guardrailsai.com/
