export const DEFAULT_PROMPT_INJECTION_PATTERNS = [
  "ignore(?:\\s+all)?\\s+(?:previous|prior|above)\\s+instructions",
  "(reveal|show|print).{0,40}(system\\s+prompt|developer\\s+message)",
  "bypass\\s+(?:safety|guardrails|security)",
  "act\\s+as\\s+(?:root|administrator|sudo)",
  "do\\s+anything\\s+now",
  "jailbreak"
];

export const DEFAULT_EXFILTRATION_PATTERNS = [
  "(upload|send|post|exfiltrat[eion]+).{0,30}(secrets?|tokens?|credentials?)",
  "copy.{0,20}(ssh|aws|api).{0,20}(key|token)",
  "export\\s+.*(env|secrets?)",
  "base64\\s+.*(?:/etc/passwd|id_rsa|credentials)"
];

export const DEFAULT_COMMAND_PATTERNS = [
  "\\brm\\s+-rf\\b",
  "\\bdd\\s+if=",
  "\\bmkfs\\b",
  "\\bshutdown\\b",
  "\\breboot\\b",
  "\\bcurl\\b.{0,40}\\|\\s*(?:sh|bash)",
  "\\bchmod\\s+777\\b",
  "\\btruncate\\s+-s\\s+0\\b"
];

export const DEFAULT_PATH_PATTERNS = [
  "\\.\\./",
  "\\.\\.\\\\",
  "^/etc/",
  "^/proc/",
  "^/sys/",
  "id_rsa",
  "\\.ssh/",
  "\\.env(?:\\.|$)",
  "node_modules/.*/\\.bin/"
];

export const DEFAULT_SHELL_OPERATOR_PATTERNS = [
  "(?:^|\\s)&&(?:\\s|$)",
  "(?:^|\\s)\\|\\|(?:\\s|$)",
  ";",
  "(?<!\\|)\\|(?!\\|)",
  "\\$\\(",
  "`",
  "(?:^|\\s)>",
  "(?:^|\\s)<",
  "\\n"
];

export const DEFAULT_SECRET_PATTERNS = [
  "AKIA[0-9A-Z]{16}",
  "(?:xox[pbar]-)[A-Za-z0-9-]{10,}",
  "(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}",
  "-----BEGIN(?: RSA)? PRIVATE KEY-----",
  "Bearer\\s+[A-Za-z0-9._-]{16,}",
  "AIza[0-9A-Za-z\\-_]{35}",
  "sk-[A-Za-z0-9]{20,}"
];

export const DEFAULT_PII_PATTERNS = [
  "[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
  "\\b\\d{3}-\\d{2}-\\d{4}\\b",
  "\\b(?:\\d[ -]*?){13,16}\\b",
  "\\+?[1-9]\\d{1,14}"
];

export function compilePatterns(patterns: string[], flags = "giu"): RegExp[] {
  return patterns.map((pattern) => new RegExp(pattern, flags));
}
