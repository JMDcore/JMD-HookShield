import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY,
  public_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider IN ('github', 'stripe', 'generic')),
  enabled INTEGER NOT NULL DEFAULT 1,
  tolerance_seconds INTEGER NOT NULL DEFAULT 300,
  max_payload_bytes INTEGER NOT NULL DEFAULT 262144,
  rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
  retention_days INTEGER NOT NULL DEFAULT 14,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_owner ON endpoints(user_id);

CREATE TABLE IF NOT EXISTS secret_versions (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  active_from TEXT NOT NULL,
  valid_until TEXT,
  retired_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(endpoint_id, version)
);
CREATE INDEX IF NOT EXISTS idx_secret_versions_endpoint ON secret_versions(endpoint_id, version DESC);

CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  provider_delivery_id TEXT,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('accepted', 'rejected', 'duplicate', 'expired', 'failed')),
  http_status INTEGER NOT NULL,
  payload_text TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  payload_bytes INTEGER NOT NULL,
  headers_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  processed_at TEXT,
  signature_valid INTEGER,
  replay_detected INTEGER NOT NULL DEFAULT 0,
  rejection_code TEXT,
  duplicate_of TEXT REFERENCES deliveries(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_endpoint_time ON deliveries(endpoint_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_deliveries_provider_id ON deliveries(endpoint_id, provider_delivery_id);

CREATE TABLE IF NOT EXISTS security_checks (
  id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('passed', 'failed', 'warning', 'skipped')),
  detail TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checks_delivery ON security_checks(delivery_id, sort_order);

CREATE TABLE IF NOT EXISTS processing_attempts (
  id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE(delivery_id, attempt_number)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
  delivery_id TEXT REFERENCES deliveries(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_owner_time ON audit_events(user_id, created_at DESC);
`;

export class HookShieldDatabase {
  readonly connection: Database.Database;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.connection = new Database(path);
    this.connection.pragma("busy_timeout = 5000");
    this.connection.exec(SCHEMA);
  }

  close(): void {
    this.connection.close();
  }

  transaction<T>(work: () => T): T {
    return this.connection.transaction(work)();
  }

  purgeExpiredSessions(now = new Date().toISOString()): number {
    return this.connection.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now).changes;
  }

  purgeExpiredDeliveries(now = new Date()): number {
    const rows = this.connection.prepare(`
      SELECT d.id
      FROM deliveries d
      JOIN endpoints e ON e.id = d.endpoint_id
      WHERE d.received_at < datetime(?, '-' || e.retention_days || ' days')
    `).all(now.toISOString()) as Array<{ id: string }>;
    const remove = this.connection.prepare("DELETE FROM deliveries WHERE id = ?");
    return this.transaction(() => rows.reduce((count, row) => count + remove.run(row.id).changes, 0));
  }
}

export type SqliteDatabase = Database.Database;
