import dns from "node:dns/promises";
import net from "node:net";
import { compilePatterns } from "../rules/patterns.js";

function stripBrackets(host: string): string {
  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

function parseIPv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const parsed = parts.map((part) => Number(part));
  if (parsed.some((value) => Number.isNaN(value) || value < 0 || value > 255)) {
    return null;
  }

  return parsed;
}

function isPrivateIPv4(ip: string): boolean {
  const parts = parseIPv4(ip);
  if (!parts) {
    return false;
  }

  const [a, b] = parts;

  if (a === 10) {
    return true;
  }

  if (a === 127) {
    return true;
  }

  if (a === 169 && b === 254) {
    return true;
  }

  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }

  if (a === 192 && b === 168) {
    return true;
  }

  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }

  if (a === 0) {
    return true;
  }

  if (a >= 224) {
    return true;
  }

  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") {
    return true;
  }

  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }

  if (normalized.startsWith("fe80")) {
    return true;
  }

  if (normalized.startsWith("ff")) {
    return true;
  }

  return false;
}

export function isPrivateOrLocalAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) {
    return isPrivateIPv4(ip);
  }

  if (family === 6) {
    return isPrivateIPv6(ip);
  }

  return false;
}

export function isHostAllowlisted(hostname: string, allowlist: string[]): boolean {
  const normalized = stripBrackets(hostname).toLowerCase();
  return allowlist.some((allowed) => allowed.toLowerCase() === normalized);
}

export function extractHostFromCandidate(candidate: string): string | null {
  const value = candidate.trim();
  if (!value) {
    return null;
  }

  if (value.includes("://")) {
    try {
      return stripBrackets(new URL(value).hostname);
    } catch {
      return null;
    }
  }

  if (/^[a-z0-9.-]+:\d+$/iu.test(value)) {
    try {
      return stripBrackets(new URL(`http://${value}`).hostname);
    } catch {
      return null;
    }
  }

  if (net.isIP(stripBrackets(value))) {
    return stripBrackets(value);
  }

  if (/^[a-z0-9.-]+$/iu.test(value)) {
    return value.toLowerCase();
  }

  return null;
}

export async function resolveHostAddresses(hostname: string): Promise<string[]> {
  const stripped = stripBrackets(hostname);
  if (net.isIP(stripped)) {
    return [stripped];
  }

  try {
    const results = await dns.lookup(stripped, { all: true });
    return Array.from(new Set(results.map((result) => result.address)));
  } catch {
    return [];
  }
}

export function containsCommandEgressPattern(command: string): boolean {
  const riskyPatterns = [
    "\\bcurl\\b",
    "\\bwget\\b",
    "\\bnc\\b",
    "\\bsocat\\b",
    "\\bftp\\b"
  ];

  return compilePatterns(riskyPatterns, "gi").some((regex) => regex.test(command));
}
