import { compilePatterns } from "../rules/patterns.js";
import { asRecord } from "./event-utils.js";

export interface ParsedCommand {
  raw: string;
  binary: string;
  args: string;
  tokens: string[];
  hasShellOperators: boolean;
  operatorHits: string[];
}

const COMMAND_KEYS = ["cmd", "command", "script", "shell", "input"] as const;

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

export function extractCommandFromArgs(args: Record<string, unknown>): string | undefined {
  const safeArgs = asRecord(args);

  for (const key of COMMAND_KEYS) {
    const value = safeArgs[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }

  return undefined;
}

export function extractUrlCandidatesFromCommand(command: string): string[] {
  return tokenize(command).filter((token) =>
    /^(?:https?|wss?|ftp):\/\//iu.test(token)
  );
}

export function parseCommand(
  rawCommand: string,
  shellOperatorPatterns: string[]
): ParsedCommand {
  const raw = rawCommand.trim();
  const tokens = tokenize(raw);
  const [binary = "", ...rest] = tokens;
  const args = rest.join(" ");

  const operatorRegexes = compilePatterns(shellOperatorPatterns, "giu");
  const operatorHits = operatorRegexes
    .filter((regex) => regex.test(raw))
    .map((regex) => regex.source);

  return {
    raw,
    binary,
    args,
    tokens,
    hasShellOperators: operatorHits.length > 0,
    operatorHits
  };
}
