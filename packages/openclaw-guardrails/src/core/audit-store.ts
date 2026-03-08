/**
 * AuditStore: Hash-chained, tamper-evident audit log in a separate SQLite file.
 *
 * Each record includes SHA-256(prev_hash + canonical_json(record)).
 * SQLite triggers prevent UPDATE/DELETE on audit_log.
 * Monthly rolling files for archival.
 */

import { createHash, randomUUID } from "node:crypto";
import type { Database, DatabaseConstructor, Statement } from "./sqlite-types.js";
import type { AuditEntry, DeniedBy } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_log (
  id                TEXT PRIMARY KEY,
  seq               INTEGER NOT NULL,
  timestamp         INTEGER NOT NULL,
  bot_instance_id   TEXT,
  actor_user_id     TEXT,
  actor_platform    TEXT,
  actor_platform_id TEXT,
  im_channel_id     TEXT,
  event_type        TEXT NOT NULL,
  decision          TEXT,
  denied_by         TEXT,
  permission_category TEXT,
  permission_action   TEXT,
  details           TEXT,
  project_id        TEXT,
  prev_hash         TEXT NOT NULL,
  event_hash        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_bot ON audit_log(bot_instance_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(actor_user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq);
`;

const TRIGGERS = `
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log records cannot be modified');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log records cannot be deleted');
END;
`;

function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export class AuditStore {
  private db: Database;
  private seq: number;
  private prevHash: string;
  private readonly insertStmt: Statement;

  constructor(dbPath: string) {
    // Dynamic require of better-sqlite3 (peer dependency)
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const BetterSqlite3 = require("better-sqlite3") as DatabaseConstructor;
    this.db = new BetterSqlite3(dbPath);

    // Exclusive locking prevents a second process from opening the audit DB
    // and forking the hash chain. WAL mode allows concurrent reads within this process.
    this.db.pragma("locking_mode = EXCLUSIVE");
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");

    this.db.exec(SCHEMA);
    this.db.exec(TRIGGERS);

    // Initialize sequence and prev_hash from last record
    const lastRow = this.db.prepare(
      "SELECT seq, event_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).get();

    if (lastRow) {
      this.seq = (lastRow.seq as number) + 1;
      this.prevHash = lastRow.event_hash as string;
    } else {
      this.seq = 1;
      this.prevHash = "0"; // genesis
    }

    this.insertStmt = this.db.prepare(`
      INSERT INTO audit_log (
        id, seq, timestamp, bot_instance_id, actor_user_id,
        actor_platform, actor_platform_id, im_channel_id,
        event_type, decision, denied_by,
        permission_category, permission_action, details,
        project_id, prev_hash, event_hash
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?
      )
    `);
  }

  append(entry: {
    botInstanceId?: string;
    actorUserId?: string;
    actorPlatform?: string;
    actorPlatformId?: string;
    imChannelId?: string;
    eventType: string;
    decision?: "allow" | "deny";
    deniedBy?: string;
    permissionCategory?: string;
    permissionAction?: string;
    details?: Record<string, unknown>;
    projectId?: string;
  }): void {
    const id = randomUUID();
    const seq = this.seq;
    const timestamp = Date.now();

    const record: Record<string, unknown> = {
      id,
      seq,
      timestamp,
      bot_instance_id: entry.botInstanceId ?? null,
      actor_user_id: entry.actorUserId ?? null,
      actor_platform: entry.actorPlatform ?? null,
      actor_platform_id: entry.actorPlatformId ?? null,
      im_channel_id: entry.imChannelId ?? null,
      event_type: entry.eventType,
      decision: entry.decision ?? null,
      denied_by: entry.deniedBy ?? null,
      permission_category: entry.permissionCategory ?? null,
      permission_action: entry.permissionAction ?? null,
      details: entry.details ? JSON.stringify(entry.details) : null,
      project_id: entry.projectId ?? null
    };

    const eventHash = sha256(this.prevHash + canonicalJson(record));

    this.insertStmt.run(
      record.id, record.seq, record.timestamp,
      record.bot_instance_id, record.actor_user_id,
      record.actor_platform, record.actor_platform_id, record.im_channel_id,
      record.event_type, record.decision, record.denied_by,
      record.permission_category, record.permission_action, record.details,
      record.project_id,
      this.prevHash, eventHash
    );

    this.prevHash = eventHash;
    this.seq += 1;
  }

  query(filters: {
    botInstanceId?: string;
    actorUserId?: string;
    eventType?: string;
    projectId?: string;
    since?: number;
    limit?: number;
  }): AuditEntry[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filters.botInstanceId) {
      conditions.push("bot_instance_id = ?");
      params.push(filters.botInstanceId);
    }
    if (filters.actorUserId) {
      conditions.push("actor_user_id = ?");
      params.push(filters.actorUserId);
    }
    if (filters.eventType) {
      conditions.push("event_type = ?");
      params.push(filters.eventType);
    }
    if (filters.projectId) {
      conditions.push("project_id = ?");
      params.push(filters.projectId);
    }
    if (filters.since) {
      conditions.push("timestamp >= ?");
      params.push(filters.since);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = filters.limit ?? 100;

    const rows = this.db.prepare(
      `SELECT * FROM audit_log ${where} ORDER BY seq DESC LIMIT ?`
    ).all(...params, limit);

    return rows.map((row) => ({
      id: row.id as string,
      seq: row.seq as number,
      timestamp: row.timestamp as number,
      botInstanceId: row.bot_instance_id as string | undefined,
      actorUserId: row.actor_user_id as string | undefined,
      actorPlatform: row.actor_platform as string | undefined,
      actorPlatformId: row.actor_platform_id as string | undefined,
      imChannelId: row.im_channel_id as string | undefined,
      eventType: row.event_type as string,
      decision: row.decision as "allow" | "deny" | undefined,
      deniedBy: row.denied_by as DeniedBy | undefined,
      permissionCategory: row.permission_category as string | undefined,
      permissionAction: row.permission_action as string | undefined,
      details: row.details ? JSON.parse(row.details as string) : undefined,
      projectId: row.project_id as string | undefined,
      prevHash: row.prev_hash as string,
      eventHash: row.event_hash as string
    }));
  }

  close(): void {
    this.db.close();
  }
}
