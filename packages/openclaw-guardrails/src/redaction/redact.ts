import { compilePatterns } from "../rules/patterns.js";

export interface RedactionResult {
  redacted: string;
  matches: string[];
}

const patternCache = new Map<string, RegExp[]>();

function getCachedPatterns(patterns: string[], flags: string): RegExp[] {
  const key = flags + "\0" + patterns.join("\0");
  let cached = patternCache.get(key);
  if (!cached) {
    cached = compilePatterns(patterns, flags);
    patternCache.set(key, cached);
  }
  return cached;
}

export function redactWithPatterns(
  input: string,
  patterns: string[],
  replacement: string
): RedactionResult {
  if (!input) {
    return {
      redacted: input,
      matches: []
    };
  }

  let redacted = input;
  const matches = new Set<string>();
  const regexes = getCachedPatterns(patterns, "gi");

  for (const regex of regexes) {
    regex.lastIndex = 0;
    for (const match of input.matchAll(regex)) {
      if (match[0]) {
        matches.add(match[0]);
      }
    }
    regex.lastIndex = 0;
    redacted = redacted.replace(regex, replacement);
  }

  return {
    redacted,
    matches: Array.from(matches)
  };
}

export function hasPatternMatch(input: string, patterns: string[]): boolean {
  if (!input) {
    return false;
  }

  const regexes = getCachedPatterns(patterns, "gi");
  return regexes.some((regex) => {
    regex.lastIndex = 0;
    return regex.test(input);
  });
}
