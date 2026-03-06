import type { ApproverRole } from "./types.js";

export interface ApprovalNotification {
  requestId: string;
  requesterId: string;
  toolName?: string;
  reason: string;
  requiredRole: ApproverRole;
  expiresAt: number;
  conversationId: string;
}

export interface NotificationSink {
  notify(notification: ApprovalNotification): void | Promise<void>;
}

export class ConsoleNotificationSink implements NotificationSink {
  notify(notification: ApprovalNotification): void {
    console.log("[guardrails:notification] approval required", {
      requestId: notification.requestId,
      requesterId: notification.requesterId,
      toolName: notification.toolName,
      reason: notification.reason,
      requiredRole: notification.requiredRole,
      expiresAt: new Date(notification.expiresAt).toISOString()
    });
  }
}

export class CallbackNotificationSink implements NotificationSink {
  constructor(
    private readonly callback: (notification: ApprovalNotification) => void | Promise<void>
  ) {}

  notify(notification: ApprovalNotification): void | Promise<void> {
    return this.callback(notification);
  }
}

export class NoopNotificationSink implements NotificationSink {
  notify(_notification: ApprovalNotification): void {
    // intentionally empty
  }
}
