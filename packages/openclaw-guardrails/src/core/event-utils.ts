import type { GuardMetadata } from "./types.js";

export function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> {
  if (isObject(value)) {
    return value;
  }
  return {};
}

export function asMetadata(value: unknown): GuardMetadata {
  if (isObject(value)) {
    return value as GuardMetadata;
  }
  return {};
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    out.push(value);
    return out;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, out);
    }
    return out;
  }

  if (isObject(value)) {
    for (const nested of Object.values(value)) {
      collectStrings(nested, out);
    }
  }

  return out;
}

export function collectPathCandidates(value: unknown): string[] {
  const candidates: string[] = [];

  if (Array.isArray(value)) {
    for (const item of value) {
      candidates.push(...collectPathCandidates(item));
    }
    return candidates;
  }

  if (!isObject(value)) {
    return candidates;
  }

  for (const [key, nested] of Object.entries(value)) {
    const keyLower = key.toLowerCase();

    if (typeof nested === "string") {
      if (
        keyLower.includes("path") ||
        keyLower.includes("file") ||
        keyLower.includes("dir") ||
        keyLower.includes("target")
      ) {
        candidates.push(nested);
      }
    } else {
      candidates.push(...collectPathCandidates(nested));
    }
  }

  return candidates;
}

export function collectNetworkCandidates(value: unknown): string[] {
  const candidates: string[] = [];

  if (Array.isArray(value)) {
    for (const item of value) {
      candidates.push(...collectNetworkCandidates(item));
    }
    return candidates;
  }

  if (!isObject(value)) {
    return candidates;
  }

  for (const [key, nested] of Object.entries(value)) {
    const keyLower = key.toLowerCase();

    if (typeof nested === "string") {
      if (
        keyLower.includes("url") ||
        keyLower.includes("host") ||
        keyLower.includes("gateway") ||
        keyLower.includes("endpoint") ||
        keyLower.includes("source")
      ) {
        candidates.push(nested);
      }
    } else {
      candidates.push(...collectNetworkCandidates(nested));
    }
  }

  return candidates;
}

export function truncate(input: string, maxChars: number): string {
  if (input.length <= maxChars) {
    return input;
  }
  return input.slice(0, maxChars);
}
