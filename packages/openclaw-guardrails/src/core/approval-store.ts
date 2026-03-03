export interface ApprovalRecord {
  requestId: string;
  actionDigest: string;
  requesterId: string;
  conversationId: string;
  requiredRole: "owner" | "admin";
  reason: string;
  createdAt: number;
  expiresAt: number;
  token?: string;
  approvedBy?: string;
  approverIds: string[];
  usedAt?: number;
}

export class ApprovalStore {
  private readonly byRequestId = new Map<string, ApprovalRecord>();
  private readonly requestIdByToken = new Map<string, string>();

  save(record: ApprovalRecord): void {
    this.byRequestId.set(record.requestId, record);
    if (record.token) {
      this.requestIdByToken.set(record.token, record.requestId);
    }
  }

  getByRequestId(requestId: string): ApprovalRecord | undefined {
    return this.byRequestId.get(requestId);
  }

  getByToken(token: string): ApprovalRecord | undefined {
    const requestId = this.requestIdByToken.get(token);
    if (!requestId) {
      return undefined;
    }
    return this.byRequestId.get(requestId);
  }

  setToken(requestId: string, token: string, approvedBy: string): ApprovalRecord | undefined {
    const record = this.byRequestId.get(requestId);
    if (!record) {
      return undefined;
    }

    if (record.token) {
      this.requestIdByToken.delete(record.token);
    }

    const updated: ApprovalRecord = {
      ...record,
      token,
      approvedBy
    };
    this.byRequestId.set(requestId, updated);
    this.requestIdByToken.set(token, requestId);
    return updated;
  }

  markUsed(requestId: string, usedAt: number): ApprovalRecord | undefined {
    const record = this.byRequestId.get(requestId);
    if (!record) {
      return undefined;
    }
    const updated: ApprovalRecord = {
      ...record,
      usedAt
    };
    this.byRequestId.set(requestId, updated);
    return updated;
  }
}
