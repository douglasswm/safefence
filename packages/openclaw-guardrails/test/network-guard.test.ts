import { describe, expect, it } from "vitest";
import {
  extractHostFromCandidate,
  isPrivateOrLocalAddress,
  isHostAllowlisted
} from "../src/core/network-guard.js";

describe("network guard", () => {
  it("extracts host from URL", () => {
    expect(extractHostFromCandidate("https://example.com/path")).toBe("example.com");
  });

  it("detects private IPs", () => {
    expect(isPrivateOrLocalAddress("10.0.0.1")).toBe(true);
    expect(isPrivateOrLocalAddress("8.8.8.8")).toBe(false);
  });

  it("matches allowlisted hosts", () => {
    expect(isHostAllowlisted("localhost", ["localhost", "127.0.0.1"]))
      .toBe(true);
  });
});
