import { describe, expect, it } from "vitest";
import { extractCommandFromArgs, parseCommand } from "../src/core/command-parse.js";
import { DEFAULT_SHELL_OPERATOR_PATTERNS } from "../src/rules/patterns.js";

describe("command parse", () => {
  it("extracts command from args", () => {
    expect(extractCommandFromArgs({ cmd: "git status" })).toBe("git status");
  });

  it("detects shell operators", () => {
    const parsed = parseCommand("git status && rm -rf /", DEFAULT_SHELL_OPERATOR_PATTERNS);

    expect(parsed.binary).toBe("git");
    expect(parsed.hasShellOperators).toBe(true);
    expect(parsed.operatorHits.length).toBeGreaterThan(0);
  });
});
