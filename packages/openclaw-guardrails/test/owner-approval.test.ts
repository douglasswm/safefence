import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { GuardrailsEngine } from "../src/core/engine.js";
import { REASON_CODES } from "../src/core/reason-codes.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";

function buildMemberToolEvent(
  conversationId = "conv-1",
  token?: string,
  requestId?: string
) {
  return {
    phase: "before_tool_call" as const,
    agentId: "agent-1",
    toolName: "exec",
    args: { cmd: "ls" },
    metadata: {
      principal: {
        senderId: "member-1",
        role: "member" as const,
        channelType: "group" as const,
        conversationId,
        mentionedAgent: true
      },
      approval: token ? { token, requestId } : undefined
    }
  };
}

describe("owner approval", () => {
  it("creates challenge and allows one-time token redemption", async () => {
    const config = createDefaultConfig("/workspace/project");
    const engine = new GuardrailsEngine(config);

    const first = await engine.evaluate(buildMemberToolEvent());
    expect(first.decision).toBe("DENY");
    expect(first.reasonCodes).toContain(REASON_CODES.OWNER_APPROVAL_REQUIRED);
    expect(first.approvalChallenge?.requestId).toBeTruthy();

    const requestId = first.approvalChallenge?.requestId as string;
    const token = engine.approveRequest(requestId, "owner-1", "owner");
    expect(token).toBeTruthy();

    const second = await engine.evaluate(buildMemberToolEvent("conv-1", token ?? undefined));
    expect(second.decision).toBe("ALLOW");

    const replay = await engine.evaluate(buildMemberToolEvent("conv-1", token ?? undefined));
    expect(replay.decision).toBe("DENY");
    expect(replay.reasonCodes).toContain(REASON_CODES.OWNER_APPROVAL_REPLAYED);
  });

  it("denies expired or mismatched approval tokens", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-03T00:00:00.000Z"));

    const config = createDefaultConfig("/workspace/project");
    config.approval.ttlSeconds = 1;
    const engine = new GuardrailsEngine(config);

    const first = await engine.evaluate(buildMemberToolEvent("conv-a"));
    const requestId = first.approvalChallenge?.requestId as string;
    const token = engine.approveRequest(requestId, "owner-1", "owner") as string;

    vi.setSystemTime(new Date("2026-03-03T00:00:02.000Z"));
    const expired = await engine.evaluate(buildMemberToolEvent("conv-a", token));
    expect(expired.decision).toBe("DENY");
    expect(expired.reasonCodes).toContain(REASON_CODES.OWNER_APPROVAL_EXPIRED);

    vi.setSystemTime(new Date("2026-03-03T00:00:03.000Z"));
    const freshRequest = await engine.evaluate(buildMemberToolEvent("conv-a"));
    const freshToken = engine.approveRequest(
      freshRequest.approvalChallenge?.requestId as string,
      "owner-1",
      "owner"
    ) as string;

    const mismatchedConversation = await engine.evaluate(
      buildMemberToolEvent("conv-b", freshToken)
    );
    expect(mismatchedConversation.decision).toBe("DENY");
    expect(mismatchedConversation.reasonCodes).toContain(
      REASON_CODES.OWNER_APPROVAL_INVALID
    );

    const mismatchedRequestId = await engine.evaluate(
      buildMemberToolEvent("conv-a", freshToken, "wrong-request-id")
    );
    expect(mismatchedRequestId.decision).toBe("DENY");
    expect(mismatchedRequestId.reasonCodes).toContain(
      REASON_CODES.OWNER_APPROVAL_INVALID
    );

    vi.useRealTimers();
  });

  it("enforces owner approval quorum before issuing token", async () => {
    const config = createDefaultConfig("/workspace/project");
    config.approval.ownerQuorum = 2;
    const engine = new GuardrailsEngine(config);

    const first = await engine.evaluate(buildMemberToolEvent("conv-q"));
    const requestId = first.approvalChallenge?.requestId as string;

    const singleApproval = engine.approveRequest(requestId, "owner-1", "owner");
    expect(singleApproval).toBeNull();

    const quorumApproval = engine.approveRequest(requestId, "owner-2", "owner");
    expect(quorumApproval).toBeTruthy();

    const allowed = await engine.evaluate(
      buildMemberToolEvent("conv-q", quorumApproval ?? undefined)
    );
    expect(allowed.decision).toBe("ALLOW");
  });

  it("persists approvals across engine restarts when storagePath is set", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-approval-"));
    const storagePath = path.join(tempDir, "approval-store.json");

    const config = createDefaultConfig(tempDir);
    config.approval.storagePath = storagePath;

    const firstEngine = new GuardrailsEngine(config);
    const first = await firstEngine.evaluate(buildMemberToolEvent("conv-p"));
    const requestId = first.approvalChallenge?.requestId as string;
    const token = firstEngine.approveRequest(requestId, "owner-1", "owner");

    expect(token).toBeTruthy();
    expect(fs.existsSync(storagePath)).toBe(true);

    const secondEngine = new GuardrailsEngine(config);
    const afterRestart = await secondEngine.evaluate(
      buildMemberToolEvent("conv-p", token ?? undefined, requestId)
    );
    expect(afterRestart.decision).toBe("ALLOW");
  });
});
