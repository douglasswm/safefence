/**
 * Structural types for better-sqlite3.
 *
 * We use structural typing so the package compiles without a hard import
 * of better-sqlite3 at build time. Shared by SqliteRoleStore and AuditStore.
 */

export interface Statement {
  run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  get(...params: unknown[]): Record<string, unknown> | undefined;
  all(...params: unknown[]): Record<string, unknown>[];
}

export interface Database {
  pragma(pragma: string): unknown;
  /** Runs raw SQL schema statements. Only pass static strings, never user input. */
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
  transaction<T>(fn: (...args: unknown[]) => T): (...args: unknown[]) => T;
}

export type DatabaseConstructor = new (filename: string, options?: Record<string, unknown>) => Database;
