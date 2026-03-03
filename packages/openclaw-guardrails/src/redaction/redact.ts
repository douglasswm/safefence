import { compilePatterns } from "../rules/patterns.js";

export interface RedactionResult {
  redacted: string;
  matches: string[];
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
  const regexes = compilePatterns(patterns, "gi");

  for (const regex of regexes) {
    for (const match of input.matchAll(regex)) {
      if (match[0]) {
        matches.add(match[0]);
      }
    }
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

  const regexes = compilePatterns(patterns, "gi");
  return regexes.some((regex) => regex.test(input));
}
