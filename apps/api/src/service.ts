import { randomBytes, randomUUID } from "node:crypto";
import type {
  CheckStatus,
  CreateEndpointInput,
  DeliveryStatus,
  DeliveryView,
  EndpointSummary,
  Provider,
  SimulatorScenario
} from "@hookshield/contracts";
import type { HookShieldDatabase } from "@hookshield/database";
import {
  decryptSecret,
  encryptSecret,
  hmacSha256,
  isTimestampFresh,
  redactHeaders,
  sha256,
  signGeneric,
  verifyGenericSignature,
  verifyGithubSignature
} from "@hookshield/security";
import Stripe from "stripe";
import { appendAudit } from "./auth.js";

interface EndpointRow {
  id: string;
  public_id: string;
  user_id: string;
  name: string;
  provider: Provider;
  enabled: number;
  tolerance_seconds: number;
  max_payload_bytes: number;
  rate_limit_per_minute: number;
  retention_days: number;
  created_at: string;
  updated_at: string;
}

interface SecretRow {
  id: string;
  version: number;
  ciphertext: string;
  iv: string;
  auth_tag: string;
  valid_until: string | null;
}

interface DeliveryRow {
  id: string;
  endpoint_id: string;
  endpoint_name: string;
  provider: Provider;
  provider_delivery_id: string | null;
  event_type: string;
  status: DeliveryStatus;
  http_status: number;
  payload_text: string;
  payload_sha256: string;
  payload_bytes: number;
  headers_json: string;
  received_at: string;
  processed_at: string | null;
  signature_valid: number | null;
  replay_detected: number;
  rejection_code: string | null;
  duplicate_of: string | null;
}

interface SecurityCheckInput {
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface ProcessResult {
  id: string;
  status: DeliveryStatus;
  httpStatus: number;
  rejectionCode: string | null;
}

interface ProcessOptions {
  forceRateLimit?: boolean;
  replayHint?: boolean;
  nowMs?: number;
}

const stripe = new Stripe("sk_test_hookshield_local_placeholder");

function readHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()] ??
    Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  return Array.isArray(value) ? value[0] : value;
}

function parseJson(raw: Buffer): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw.toString("utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function eventTypeFromJson(payload: Record<string, unknown> | null): string {
  return typeof payload?.type === "string" ? payload.type.slice(0, 120) : "unknown";
}

export class HookShieldService {
  private readonly rateWindows = new Map<string, number[]>();

  constructor(
    private readonly db: HookShieldDatabase,
    private readonly masterKey: Buffer,
    private readonly apiBaseUrl: string
  ) {}

  createEndpoint(userId: string, input: CreateEndpointInput): EndpointSummary {
    const id = randomUUID();
    const publicId = randomBytes(32).toString("base64url");
    const now = new Date().toISOString();
    const encrypted = encryptSecret(input.secret, this.masterKey);
    this.db.transaction(() => {
      this.db.connection.prepare(`
        INSERT INTO endpoints
          (id, public_id, user_id, name, provider, enabled, tolerance_seconds,
           max_payload_bytes, rate_limit_per_minute, retention_days, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
      `).run(
        id, publicId, userId, input.name, input.provider, input.toleranceSeconds,
        input.maxPayloadBytes, input.rateLimitPerMinute, input.retentionDays, now, now
      );
      this.db.connection.prepare(`
        INSERT INTO secret_versions
          (id, endpoint_id, version, ciphertext, iv, auth_tag, active_from, valid_until, retired_at, created_at)
        VALUES (?, ?, 1, ?, ?, ?, ?, NULL, NULL, ?)
      `).run(randomUUID(), id, encrypted.ciphertext, encrypted.iv, encrypted.authTag, now, now);
      appendAudit(this.db, {
        userId,
        endpointId: id,
        action: "endpoint.created",
        outcome: "success",
        metadata: { provider: input.provider, name: input.name }
      });
    });
    return this.getEndpoint(userId, id)!;
  }

  getEndpoint(userId: string, endpointId: string): EndpointSummary | null {
    const row = this.db.connection.prepare(`
      SELECT e.*,
        COALESCE((SELECT MAX(version) FROM secret_versions WHERE endpoint_id = e.id), 0) AS secret_version
      FROM endpoints e WHERE e.id = ? AND e.user_id = ?
    `).get(endpointId, userId) as (EndpointRow & { secret_version: number }) | undefined;
    return row ? this.mapEndpoint(row) : null;
  }

  listEndpoints(userId: string): EndpointSummary[] {
    const rows = this.db.connection.prepare(`
      SELECT e.*,
        COALESCE((SELECT MAX(version) FROM secret_versions WHERE endpoint_id = e.id), 0) AS secret_version
      FROM endpoints e WHERE e.user_id = ? ORDER BY e.created_at ASC
    `).all(userId) as Array<EndpointRow & { secret_version: number }>;
    return rows.map((row) => this.mapEndpoint(row));
  }

  updateEndpoint(
    userId: string,
    endpointId: string,
    input: Partial<{
      name: string;
      enabled: boolean;
      toleranceSeconds: number;
      maxPayloadBytes: number;
      rateLimitPerMinute: number;
      retentionDays: number;
    }>
  ): EndpointSummary | null {
    const existing = this.getEndpoint(userId, endpointId);
    if (!existing) return null;
    this.db.connection.prepare(`
      UPDATE endpoints SET name = ?, enabled = ?, tolerance_seconds = ?, max_payload_bytes = ?,
        rate_limit_per_minute = ?, retention_days = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `).run(
      input.name ?? existing.name,
      input.enabled === undefined ? Number(existing.enabled) : Number(input.enabled),
      input.toleranceSeconds ?? existing.toleranceSeconds,
      input.maxPayloadBytes ?? existing.maxPayloadBytes,
      input.rateLimitPerMinute ?? existing.rateLimitPerMinute,
      input.retentionDays ?? existing.retentionDays,
      new Date().toISOString(),
      endpointId,
      userId
    );
    appendAudit(this.db, {
      userId, endpointId, action: "endpoint.updated", outcome: "success",
      metadata: { fields: Object.keys(input) }
    });
    return this.getEndpoint(userId, endpointId);
  }

  deleteEndpoint(userId: string, endpointId: string): boolean {
    const existing = this.getEndpoint(userId, endpointId);
    if (!existing) return false;
    appendAudit(this.db, {
      userId, endpointId, action: "endpoint.deleted", outcome: "success",
      metadata: { name: existing.name, provider: existing.provider }
    });
    return this.db.connection.prepare("DELETE FROM endpoints WHERE id = ? AND user_id = ?")
      .run(endpointId, userId).changes === 1;
  }

  rotateSecret(userId: string, endpointId: string, secret: string, transitionSeconds: number): EndpointSummary | null {
    const endpoint = this.getEndpoint(userId, endpointId);
    if (!endpoint) return null;
    const now = new Date();
    const validUntil = new Date(now.getTime() + transitionSeconds * 1000).toISOString();
    const encrypted = encryptSecret(secret, this.masterKey);
    this.db.transaction(() => {
      this.db.connection.prepare(`
        UPDATE secret_versions SET retired_at = ?, valid_until = ?
        WHERE endpoint_id = ? AND retired_at IS NULL
      `).run(now.toISOString(), validUntil, endpointId);
      this.db.connection.prepare(`
        INSERT INTO secret_versions
          (id, endpoint_id, version, ciphertext, iv, auth_tag, active_from, valid_until, retired_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
      `).run(
        randomUUID(), endpointId, endpoint.secretVersion + 1, encrypted.ciphertext,
        encrypted.iv, encrypted.authTag, now.toISOString(), now.toISOString()
      );
      appendAudit(this.db, {
        userId, endpointId, action: "secret.rotated", outcome: "success",
        metadata: { version: endpoint.secretVersion + 1, transitionSeconds }
      });
    });
    return this.getEndpoint(userId, endpointId);
  }

  private mapEndpoint(row: EndpointRow & { secret_version: number }): EndpointSummary {
    return {
      id: row.id,
      publicId: row.public_id,
      name: row.name,
      provider: row.provider,
      enabled: Boolean(row.enabled),
      toleranceSeconds: row.tolerance_seconds,
      maxPayloadBytes: row.max_payload_bytes,
      rateLimitPerMinute: row.rate_limit_per_minute,
      retentionDays: row.retention_days,
      secretVersion: row.secret_version,
      ingestUrl: `${this.apiBaseUrl}/hooks/${row.public_id}`,
      createdAt: row.created_at
    };
  }

  getEndpointByPublicId(publicId: string): EndpointRow | null {
    return (this.db.connection.prepare("SELECT * FROM endpoints WHERE public_id = ?")
      .get(publicId) as EndpointRow | undefined) ?? null;
  }

  private getEndpointByIdForOwner(endpointId: string, userId: string): EndpointRow | null {
    return (this.db.connection.prepare("SELECT * FROM endpoints WHERE id = ? AND user_id = ?")
      .get(endpointId, userId) as EndpointRow | undefined) ?? null;
  }

  private usableSecrets(endpointId: string, nowIso: string): Array<SecretRow & { secret: string }> {
    const rows = this.db.connection.prepare(`
      SELECT id, version, ciphertext, iv, auth_tag, valid_until
      FROM secret_versions
      WHERE endpoint_id = ? AND (valid_until IS NULL OR valid_until >= ?)
      ORDER BY version DESC
    `).all(endpointId, nowIso) as SecretRow[];
    return rows.map((row) => ({
      ...row,
      secret: decryptSecret({
        ciphertext: row.ciphertext,
        iv: row.iv,
        authTag: row.auth_tag
      }, this.masterKey)
    }));
  }

  private isRateLimited(endpoint: EndpointRow, nowMs: number, forced: boolean): boolean {
    if (forced) return true;
    const cutoff = nowMs - 60_000;
    const current = (this.rateWindows.get(endpoint.id) ?? []).filter((time) => time > cutoff);
    current.push(nowMs);
    this.rateWindows.set(endpoint.id, current);
    return current.length > endpoint.rate_limit_per_minute;
  }

  processWebhook(
    endpoint: EndpointRow,
    rawBody: Buffer,
    headers: Record<string, string | string[] | undefined>,
    options: ProcessOptions = {}
  ): ProcessResult {
    const nowMs = options.nowMs ?? Date.now();
    const now = new Date(nowMs);
    const checks: SecurityCheckInput[] = [];
    let providerDeliveryId: string | null = null;
    let eventType = "unknown";
    let signatureValid: boolean | null = null;
    let replayDetected = Boolean(options.replayHint);
    let status: DeliveryStatus = "rejected";
    let httpStatus = 401;
    let rejectionCode: string | null = "SIGNATURE_INVALID";
    let duplicateOf: string | null = null;
    const parsedPayload = parseJson(rawBody);

    const oversized = rawBody.length > endpoint.max_payload_bytes;
    checks.push({
      name: "Payload size",
      status: oversized ? "failed" : "passed",
      detail: oversized
        ? `${rawBody.length.toLocaleString()} bytes exceeds the ${endpoint.max_payload_bytes.toLocaleString()} byte limit.`
        : `${rawBody.length.toLocaleString()} bytes is within the endpoint limit.`
    });

    const rateLimited = this.isRateLimited(endpoint, nowMs, Boolean(options.forceRateLimit));
    checks.push({
      name: "Rate limit",
      status: rateLimited ? "failed" : "passed",
      detail: rateLimited
        ? "The endpoint minute window is exhausted."
        : `Request admitted under the ${endpoint.rate_limit_per_minute}/minute endpoint policy.`
    });

    if (!endpoint.enabled) {
      status = "rejected";
      httpStatus = 404;
      rejectionCode = "ENDPOINT_DISABLED";
      checks.push({ name: "Endpoint state", status: "failed", detail: "This endpoint is disabled." });
    } else if (oversized) {
      status = "rejected";
      httpStatus = 413;
      rejectionCode = "PAYLOAD_TOO_LARGE";
    } else if (rateLimited) {
      status = "rejected";
      httpStatus = 429;
      rejectionCode = "RATE_LIMITED";
    } else {
      const secrets = this.usableSecrets(endpoint.id, now.toISOString());
      let matchedVersion: number | null = null;
      let freshness: boolean | null = endpoint.provider === "github" ? null : false;
      let verificationReason = "mismatch";

      if (endpoint.provider === "github") {
        providerDeliveryId = readHeader(headers, "x-github-delivery") ?? null;
        eventType = readHeader(headers, "x-github-event")?.slice(0, 120) ?? "unknown";
        const signature = readHeader(headers, "x-hub-signature-256");
        for (const secret of secrets) {
          const result = verifyGithubSignature(rawBody, signature, secret.secret);
          verificationReason = result.reason;
          if (result.valid) {
            signatureValid = true;
            matchedVersion = secret.version;
            break;
          }
        }
        signatureValid ??= false;
      } else if (endpoint.provider === "generic") {
        const timestamp = readHeader(headers, "x-hookshield-timestamp") ?? "";
        providerDeliveryId = readHeader(headers, "x-hookshield-delivery") ?? null;
        eventType = eventTypeFromJson(parsedPayload);
        const signature = readHeader(headers, "x-hookshield-signature");
        for (const secret of secrets) {
          const result = verifyGenericSignature(
            rawBody, signature, timestamp, providerDeliveryId ?? "", secret.secret
          );
          verificationReason = result.reason;
          if (result.valid) {
            signatureValid = true;
            matchedVersion = secret.version;
            break;
          }
        }
        signatureValid ??= false;
        freshness = isTimestampFresh(timestamp, endpoint.tolerance_seconds, nowMs);
      } else {
        const signature = readHeader(headers, "stripe-signature");
        const timestamp = signature?.split(",").find((part) => part.startsWith("t="))?.slice(2) ?? "";
        if (!signature) {
          signatureValid = false;
          verificationReason = "missing";
        } else {
          for (const secret of secrets) {
            try {
              const event = stripe.webhooks.constructEvent(rawBody, signature, secret.secret, 0);
              signatureValid = true;
              matchedVersion = secret.version;
              providerDeliveryId = event.id;
              eventType = event.type;
              verificationReason = "valid";
              break;
            } catch {
              verificationReason = "mismatch";
            }
          }
          signatureValid ??= false;
        }
        freshness = isTimestampFresh(timestamp, endpoint.tolerance_seconds, nowMs);
      }

      checks.push({
        name: "Cryptographic signature",
        status: signatureValid ? "passed" : "failed",
        detail: signatureValid
          ? `Signature matched secret version ${matchedVersion}.`
          : `Signature verification failed (${verificationReason}).`
      });
      checks.push({
        name: "Freshness window",
        status: freshness === null ? "warning" : freshness ? "passed" : "failed",
        detail: freshness === null
          ? "GitHub's standard signature has no signed timestamp; freshness is not asserted."
          : freshness
            ? `Signed timestamp is inside the ${endpoint.tolerance_seconds} second window.`
            : `Signed timestamp is missing, malformed, or outside the ${endpoint.tolerance_seconds} second window.`
      });

      const jsonValid = parsedPayload !== null;
      checks.push({
        name: "JSON structure",
        status: jsonValid ? "passed" : "failed",
        detail: jsonValid ? "Payload is a bounded JSON object." : "Payload is not a valid JSON object."
      });

      if (providerDeliveryId) {
        const existing = this.db.connection.prepare(`
          SELECT id FROM deliveries
          WHERE endpoint_id = ? AND provider_delivery_id = ?
            AND status IN ('accepted', 'duplicate')
          ORDER BY received_at ASC LIMIT 1
        `).get(endpoint.id, providerDeliveryId) as { id: string } | undefined;
        duplicateOf = existing?.id ?? null;
      }
      checks.push({
        name: "Delivery idempotency",
        status: !providerDeliveryId ? "failed" : duplicateOf ? "failed" : "passed",
        detail: !providerDeliveryId
          ? "The provider delivery identifier is missing."
          : duplicateOf
            ? "This delivery identifier was already processed."
            : "Delivery identifier has not been observed for this endpoint."
      });

      if (!signatureValid) {
        status = "rejected";
        httpStatus = 401;
        rejectionCode = "SIGNATURE_INVALID";
      } else if (freshness === false) {
        status = "expired";
        httpStatus = 400;
        rejectionCode = "TIMESTAMP_EXPIRED";
        replayDetected = true;
      } else if (!providerDeliveryId) {
        status = "rejected";
        httpStatus = 400;
        rejectionCode = "MISSING_DELIVERY_ID";
      } else if (!jsonValid) {
        status = "rejected";
        httpStatus = 400;
        rejectionCode = "MALFORMED_JSON";
      } else if (duplicateOf) {
        status = "duplicate";
        httpStatus = 200;
        rejectionCode = "DUPLICATE_DELIVERY";
        replayDetected = true;
      } else {
        status = "accepted";
        httpStatus = 202;
        rejectionCode = null;
      }
    }

    const id = randomUUID();
    const receivedAt = now.toISOString();
    const processedAt = new Date(nowMs + 8).toISOString();
    const payloadText = oversized
      ? `${rawBody.subarray(0, 8192).toString("utf8")}\n[TRUNCATED BY HOOKSHIELD]`
      : rawBody.toString("utf8");
    this.db.transaction(() => {
      this.db.connection.prepare(`
        INSERT INTO deliveries
          (id, endpoint_id, provider_delivery_id, event_type, status, http_status, payload_text,
           payload_sha256, payload_bytes, headers_json, received_at, processed_at, signature_valid,
           replay_detected, rejection_code, duplicate_of)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, endpoint.id, providerDeliveryId, eventType, status, httpStatus, payloadText,
        sha256(rawBody), rawBody.length, JSON.stringify(redactHeaders(headers)), receivedAt,
        processedAt, signatureValid === null ? null : Number(signatureValid), Number(replayDetected),
        rejectionCode, duplicateOf
      );
      const insertCheck = this.db.connection.prepare(`
        INSERT INTO security_checks (id, delivery_id, name, status, detail, sort_order, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      checks.forEach((check, index) => {
        insertCheck.run(randomUUID(), id, check.name, check.status, check.detail, index, receivedAt);
      });
      this.db.connection.prepare(`
        INSERT INTO processing_attempts
          (id, delivery_id, attempt_number, status, detail, started_at, completed_at)
        VALUES (?, ?, 1, ?, ?, ?, ?)
      `).run(
        randomUUID(), id, status === "accepted" ? "processed" : "not_processed",
        status === "accepted"
          ? "Accepted by the controlled internal consumer."
          : `Processing stopped by security decision: ${rejectionCode ?? status}.`,
        receivedAt, processedAt
      );
      appendAudit(this.db, {
        userId: endpoint.user_id,
        endpointId: endpoint.id,
        deliveryId: id,
        action: "delivery.evaluated",
        outcome: status,
        metadata: { eventType, rejectionCode, payloadBytes: rawBody.length }
      });
    });
    return { id, status, httpStatus, rejectionCode };
  }

  listDeliveries(
    userId: string,
    filters: { endpointId?: string; status?: DeliveryStatus; query?: string } = {}
  ): DeliveryView[] {
    const conditions = ["e.user_id = ?"];
    const values: unknown[] = [userId];
    if (filters.endpointId) {
      conditions.push("d.endpoint_id = ?");
      values.push(filters.endpointId);
    }
    if (filters.status) {
      conditions.push("d.status = ?");
      values.push(filters.status);
    }
    if (filters.query) {
      conditions.push("(d.event_type LIKE ? OR d.provider_delivery_id LIKE ?)");
      values.push(`%${filters.query}%`, `%${filters.query}%`);
    }
    const rows = this.db.connection.prepare(`
      SELECT d.*, e.name AS endpoint_name, e.provider
      FROM deliveries d JOIN endpoints e ON e.id = d.endpoint_id
      WHERE ${conditions.join(" AND ")}
      ORDER BY d.received_at DESC LIMIT 200
    `).all(...values) as DeliveryRow[];
    return rows.map((row) => this.mapDelivery(row, false));
  }

  getDelivery(userId: string, deliveryId: string): DeliveryView | null {
    const row = this.db.connection.prepare(`
      SELECT d.*, e.name AS endpoint_name, e.provider
      FROM deliveries d JOIN endpoints e ON e.id = d.endpoint_id
      WHERE d.id = ? AND e.user_id = ?
    `).get(deliveryId, userId) as DeliveryRow | undefined;
    return row ? this.mapDelivery(row, true) : null;
  }

  private mapDelivery(row: DeliveryRow, includeEvidence: boolean): DeliveryView {
    const checks = includeEvidence ? this.db.connection.prepare(`
      SELECT id, name, status, detail, sort_order AS sortOrder
      FROM security_checks WHERE delivery_id = ? ORDER BY sort_order
    `).all(row.id) as DeliveryView["checks"] : [];
    const timeline = includeEvidence ? this.db.connection.prepare(`
      SELECT id, attempt_number AS attemptNumber, status, detail,
        started_at AS startedAt, completed_at AS completedAt
      FROM processing_attempts WHERE delivery_id = ? ORDER BY attempt_number
    `).all(row.id) as DeliveryView["timeline"] : [];
    return {
      id: row.id,
      endpointId: row.endpoint_id,
      endpointName: row.endpoint_name,
      provider: row.provider,
      providerDeliveryId: row.provider_delivery_id,
      eventType: row.event_type,
      status: row.status,
      httpStatus: row.http_status,
      payload: row.payload_text,
      payloadSha256: row.payload_sha256,
      payloadBytes: row.payload_bytes,
      headers: JSON.parse(row.headers_json) as Record<string, string>,
      receivedAt: row.received_at,
      processedAt: row.processed_at,
      signatureValid: row.signature_valid === null ? null : Boolean(row.signature_valid),
      replayDetected: Boolean(row.replay_detected),
      rejectionCode: row.rejection_code,
      duplicateOf: row.duplicate_of,
      checks,
      timeline
    };
  }

  retryDelivery(userId: string, deliveryId: string): DeliveryView | null {
    const delivery = this.getDelivery(userId, deliveryId);
    if (!delivery || !["accepted", "failed"].includes(delivery.status)) return null;
    const count = this.db.connection.prepare(
      "SELECT COUNT(*) AS count FROM processing_attempts WHERE delivery_id = ?"
    ).get(deliveryId) as { count: number };
    if (count.count >= 3) return null;
    const now = new Date().toISOString();
    this.db.connection.prepare(`
      INSERT INTO processing_attempts
        (id, delivery_id, attempt_number, status, detail, started_at, completed_at)
      VALUES (?, ?, ?, 'processed', 'Controlled internal consumer retry completed.', ?, ?)
    `).run(randomUUID(), deliveryId, count.count + 1, now, now);
    appendAudit(this.db, {
      userId, endpointId: delivery.endpointId, deliveryId,
      action: "delivery.retried", outcome: "success", metadata: { attempt: count.count + 1 }
    });
    return this.getDelivery(userId, deliveryId);
  }

  dashboardSummary(userId: string) {
    const counts = this.db.connection.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN d.status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
        SUM(CASE WHEN d.status IN ('rejected', 'expired', 'failed') THEN 1 ELSE 0 END) AS rejected,
        SUM(CASE WHEN d.status = 'duplicate' THEN 1 ELSE 0 END) AS duplicate
      FROM deliveries d JOIN endpoints e ON e.id = d.endpoint_id
      WHERE e.user_id = ? AND d.received_at >= datetime('now', '-1 day')
    `).get(userId) as { total: number; accepted: number | null; rejected: number | null; duplicate: number | null };
    const total = counts.total ?? 0;
    const accepted = counts.accepted ?? 0;
    return {
      total24h: total,
      accepted24h: accepted,
      rejected24h: counts.rejected ?? 0,
      duplicate24h: counts.duplicate ?? 0,
      acceptanceRate: total === 0 ? 0 : Math.round((accepted / total) * 1000) / 10
    };
  }

  exportAudit(userId: string) {
    const events = this.db.connection.prepare(`
      SELECT id, endpoint_id AS endpointId, delivery_id AS deliveryId,
        action, outcome, metadata_json AS metadata, created_at AS createdAt
      FROM audit_events WHERE user_id = ? ORDER BY created_at DESC
    `).all(userId) as Array<{
      id: string; endpointId: string | null; deliveryId: string | null;
      action: string; outcome: string; metadata: string; createdAt: string;
    }>;
    return {
      format: "hookshield.audit.v1",
      exportedAt: new Date().toISOString(),
      events: events.map((event) => ({ ...event, metadata: JSON.parse(event.metadata) as unknown }))
    };
  }

  purgeRetention(userId: string): number {
    const endpoints = this.listEndpoints(userId);
    const ids = new Set(endpoints.map((endpoint) => endpoint.id));
    const now = new Date();
    const rows = this.db.connection.prepare(`
      SELECT d.id, d.endpoint_id, d.received_at, e.retention_days
      FROM deliveries d JOIN endpoints e ON e.id = d.endpoint_id WHERE e.user_id = ?
    `).all(userId) as Array<{ id: string; endpoint_id: string; received_at: string; retention_days: number }>;
    const remove = this.db.connection.prepare("DELETE FROM deliveries WHERE id = ?");
    const deleted = this.db.transaction(() => rows.reduce((count, row) => {
      const cutoff = now.getTime() - row.retention_days * 86_400_000;
      return ids.has(row.endpoint_id) && new Date(row.received_at).getTime() < cutoff
        ? count + remove.run(row.id).changes
        : count;
    }, 0));
    appendAudit(this.db, {
      userId, action: "retention.purged", outcome: "success", metadata: { deleted }
    });
    return deleted;
  }

  simulate(userId: string, endpointId: string, scenario: SimulatorScenario): ProcessResult {
    if (scenario === "valid_after_rotation") {
      this.rotateSecret(userId, endpointId, randomBytes(32).toString("base64url"), 3600);
    }
    const endpoint = this.getEndpointByIdForOwner(endpointId, userId);
    if (!endpoint) throw new Error("ENDPOINT_NOT_FOUND");
    const secrets = this.usableSecrets(endpoint.id, new Date().toISOString());
    const currentSecret = secrets[0]?.secret;
    if (!currentSecret) throw new Error("SECRET_NOT_FOUND");
    const timestamp = String(Math.floor(Date.now() / 1000));
    const deliveryId = `sim_${randomBytes(9).toString("hex")}`;
    const payloadObject = endpoint.provider === "stripe"
      ? { id: deliveryId, object: "event", type: "payment_intent.succeeded", data: { object: { id: "pi_demo", amount: 4200 } } }
      : { type: endpoint.provider === "github" ? "push" : "deployment.completed", source: "hookshield-simulator", sequence: 42 };
    let rawBody = Buffer.from(JSON.stringify(payloadObject));
    const headers: Record<string, string> = { "content-type": "application/json" };

    const sign = (body: Buffer, time = timestamp): void => {
      if (endpoint.provider === "github") {
        headers["x-hub-signature-256"] = `sha256=${hmacSha256(currentSecret, body)}`;
        headers["x-github-delivery"] = deliveryId;
        headers["x-github-event"] = "push";
      } else if (endpoint.provider === "generic") {
        headers["x-hookshield-timestamp"] = time;
        headers["x-hookshield-delivery"] = deliveryId;
        headers["x-hookshield-signature"] = signGeneric(body, time, deliveryId, currentSecret);
      } else {
        headers["stripe-signature"] = stripe.webhooks.generateTestHeaderString({
          payload: body.toString("utf8"), secret: currentSecret, timestamp: Number(time)
        });
      }
    };

    if (scenario === "oversized_payload") {
      rawBody = Buffer.from(JSON.stringify({ type: "oversized", data: "x".repeat(endpoint.max_payload_bytes + 1) }));
      sign(rawBody);
      return this.processWebhook(endpoint, rawBody, headers);
    }
    if (scenario === "expired_timestamp" || scenario === "replay") {
      const expired = String(Math.floor(Date.now() / 1000) - endpoint.tolerance_seconds - 30);
      sign(rawBody, expired);
      return this.processWebhook(endpoint, rawBody, headers, { replayHint: scenario === "replay" });
    }
    if (scenario === "tampered_payload") {
      sign(rawBody);
      rawBody = Buffer.from(JSON.stringify({ ...payloadObject, sequence: 9001, tampered: true }));
      return this.processWebhook(endpoint, rawBody, headers);
    }
    sign(rawBody);
    if (scenario === "invalid_signature") {
      const signatureName = endpoint.provider === "github"
        ? "x-hub-signature-256"
        : endpoint.provider === "stripe" ? "stripe-signature" : "x-hookshield-signature";
      headers[signatureName] = endpoint.provider === "stripe"
        ? `t=${timestamp},v1=${"0".repeat(64)}`
        : `sha256=${"0".repeat(64)}`;
    }
    if (scenario === "rate_limited") {
      return this.processWebhook(endpoint, rawBody, headers, { forceRateLimit: true });
    }
    if (scenario === "duplicate") {
      this.processWebhook(endpoint, rawBody, headers);
      return this.processWebhook(endpoint, rawBody, headers, { replayHint: true });
    }
    return this.processWebhook(endpoint, rawBody, headers);
  }
}
