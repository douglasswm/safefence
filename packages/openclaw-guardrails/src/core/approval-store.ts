import fs from "node:fs";
import path from "node:path";
import type { ApproverRole } from "./types.js";

export interface ApprovalRecord {
  requestId: string;
  actionDigest: string;
  requesterId: string;
  conversationId: string;
  requiredRole: ApproverRole;
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
  private readonly storagePath?: string;

  constructor(storagePath?: string, allowedRoot?: string) {
    if (storagePath && allowedRoot) {
      const resolved = path.resolve(storagePath);
      const resolvedRoot = path.resolve(allowedRoot);
      if (!resolved.startsWith(resolvedRoot + path.sep) && resolved !== resolvedRoot) {
        throw new Error(`storagePath must be within ${resolvedRoot}`);
      }
    }
    this.storagePath = storagePath;
    this.loadFromDisk();
  }

  save(record: ApprovalRecord): void {
    this.byRequestId.set(record.requestId, record);
    if (record.token) {
      this.requestIdByToken.set(record.token, record.requestId);
    }
    this.flushToDisk();
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
    this.flushToDisk();
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
    this.pruneExpired(usedAt);
    this.flushToDisk();
    return updated;
  }

  private pruneExpired(nowMs: number): void {
    for (const [id, record] of this.byRequestId) {
      // Prune all expired records. Non-expired records must be retained for replay detection.
      if (record.expiresAt <= nowMs) {
        if (record.token) {
          this.requestIdByToken.delete(record.token);
        }
        this.byRequestId.delete(id);
      }
    }
  }

  private loadFromDisk(): void {
    if (!this.storagePath) {
      return;
    }

    try {
      const raw = fs.readFileSync(this.storagePath, "utf8");
      const parsed = JSON.parse(raw) as ApprovalRecord[];

      if (!Array.isArray(parsed)) {
        return;
      }

      const nowMs = Date.now();
      for (const record of parsed) {
        if (!record || typeof record.requestId !== "string") {
          continue;
        }
        if (record.expiresAt <= nowMs || record.usedAt) {
          continue;
        }
        this.byRequestId.set(record.requestId, record);
        if (record.token) {
          this.requestIdByToken.set(record.token, record.requestId);
        }
      }
    } catch {
      // Fail closed at higher layers; ignore corrupted persistence artifacts here.
    }
  }

  private flushToDisk(): void {
    if (!this.storagePath) {
      return;
    }

    try {
      const dir = path.dirname(this.storagePath);
      fs.mkdirSync(dir, { recursive: true });

      const nowMs = Date.now();
      const records = Array.from(this.byRequestId.values()).filter(
        (record) => !record.usedAt && record.expiresAt > nowMs
      );
      const tempPath = `${this.storagePath}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(records, null, 2), "utf8");
      fs.renameSync(tempPath, this.storagePath);
    } catch {
      // Best-effort durability; in-memory state remains authoritative for this process.
    }
  }
}
