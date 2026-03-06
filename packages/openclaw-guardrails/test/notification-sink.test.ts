import { describe, expect, it, vi } from "vitest";
import {
  ConsoleNotificationSink,
  CallbackNotificationSink,
  NoopNotificationSink
} from "../src/core/notification-sink.js";
import type { ApprovalNotification } from "../src/core/notification-sink.js";
import { ApprovalBroker } from "../src/core/approval.js";
import { createDefaultConfig } from "../src/rules/default-policy.js";
import type { NormalizedEvent } from "../src/core/types.js";

function makeNotification(overrides: Partial<ApprovalNotification> = {}): ApprovalNotification {
  return {
    requestId: "req-1",
    requesterId: "user-1",
    toolName: "exec",
    reason: "Restricted tool requires approval",
    requiredRole: "owner",
    expiresAt: Date.now() + 300_000,
    conversationId: "conv-1",
    ...overrides
  };
}

describe("ConsoleNotificationSink", () => {
  it("logs notification without throwing", () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const sink = new ConsoleNotificationSink();
    sink.notify(makeNotification());
    expect(consoleSpy).toHaveBeenCalledTimes(1);
    consoleSpy.mockRestore();
  });
});

describe("CallbackNotificationSink", () => {
  it("invokes callback with notification", () => {
    const cb = vi.fn();
    const sink = new CallbackNotificationSink(cb);
    const notification = makeNotification();
    sink.notify(notification);
    expect(cb).toHaveBeenCalledWith(notification);
  });

  it("supports async callback", async () => {
    const cb = vi.fn().mockResolvedValue(undefined);
    const sink = new CallbackNotificationSink(cb);
    await sink.notify(makeNotification());
    expect(cb).toHaveBeenCalledTimes(1);
  });
});

describe("NoopNotificationSink", () => {
  it("does not throw", () => {
    const sink = new NoopNotificationSink();
    expect(() => sink.notify(makeNotification())).not.toThrow();
  });
});

describe("ApprovalBroker notification integration", () => {
  it("notifies sink when challenge is created", () => {
    const config = createDefaultConfig("/workspace");
    config.notifications.enabled = true;
    config.principal.ownerIds = ["owner-1"];

    const cb = vi.fn();
    const sink = new CallbackNotificationSink(cb);
    const broker = new ApprovalBroker(config, undefined, sink);

    const event: NormalizedEvent = {
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: {},
      metadata: {
        principal: {
          senderId: "user-1",
          role: "member",
          conversationId: "conv-1",
          channelType: "dm"
        }
      }
    };

    broker.createChallenge({
      event,
      requirement: {
        reason: "Restricted tool",
        requiredRole: "owner"
      }
    });

    expect(cb).toHaveBeenCalledTimes(1);
    const notification = cb.mock.calls[0][0] as ApprovalNotification;
    expect(notification.requesterId).toBe("user-1");
    expect(notification.toolName).toBe("exec");
    expect(notification.requiredRole).toBe("owner");
  });

  it("does not notify when notifications are disabled", () => {
    const config = createDefaultConfig("/workspace");
    config.notifications.enabled = false;

    const cb = vi.fn();
    const sink = new CallbackNotificationSink(cb);
    const broker = new ApprovalBroker(config, undefined, sink);

    const event: NormalizedEvent = {
      phase: "before_tool_call",
      agentId: "agent-1",
      toolName: "exec",
      args: {},
      metadata: {
        principal: {
          senderId: "user-1",
          role: "member",
          conversationId: "conv-1",
          channelType: "dm"
        }
      }
    };

    broker.createChallenge({
      event,
      requirement: {
        reason: "Restricted tool",
        requiredRole: "owner"
      }
    });

    expect(cb).not.toHaveBeenCalled();
  });
});
