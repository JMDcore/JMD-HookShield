import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashPassword, hmacSha256, signGeneric } from "@hookshield/security";
import type { FastifyInstance } from "fastify";
import type { HookShieldDatabase } from "@hookshield/database";
import type { HookShieldService } from "./service.js";
import { buildApp } from "./app.js";

interface TestContext {
  app: FastifyInstance;
  db: HookShieldDatabase;
  service: HookShieldService;
  owner: { id: string; email: string; password: string };
  other: { id: string; email: string; password: string };
}

let context: TestContext;

function insertUser(
  db: HookShieldDatabase,
  input: { id: string; email: string; password: string }
): void {
  db.connection.prepare(`
    INSERT INTO users (id, email, name, password_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(input.id, input.email, input.email.split("@")[0], hashPassword(input.password), new Date().toISOString());
}

async function login(user: { email: string; password: string }) {
  const response = await context.app.inject({
    method: "POST",
    url: "/api/auth/login",
    payload: { email: user.email, password: user.password }
  });
  expect(response.statusCode).toBe(200);
  const setCookie = response.headers["set-cookie"];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(";")[0];
  const body = response.json() as { csrfToken: string };
  return { cookie: cookie!, csrf: body.csrfToken };
}

function genericHeaders(body: Buffer, secret: string, deliveryId: string, timestamp?: string) {
  const signedAt = timestamp ?? String(Math.floor(Date.now() / 1000));
  return {
    "content-type": "application/json",
    "x-hookshield-delivery": deliveryId,
    "x-hookshield-timestamp": signedAt,
    "x-hookshield-signature": signGeneric(body, signedAt, deliveryId, secret)
  };
}

beforeEach(async () => {
  process.env.NODE_ENV = "test";
  const built = await buildApp({
    databasePath: ":memory:",
    masterKey: Buffer.alloc(32, 9),
    port: 8787,
    webOrigin: "http://localhost:3000",
    demoMode: true,
    secureCookies: false
  });
  const owner = { id: randomUUID(), email: "owner@example.test", password: "owner-password-long" };
  const other = { id: randomUUID(), email: "other@example.test", password: "other-password-long" };
  insertUser(built.db, owner);
  insertUser(built.db, other);
  context = { ...built, owner, other };
});

afterEach(async () => {
  await context.app.close();
});

describe("webhook ingress decisions", () => {
  it("accepts a signed event and records a duplicate as replay evidence", async () => {
    const secret = "integration-secret-with-entropy";
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Generic integration",
      provider: "generic",
      secret,
      toleranceSeconds: 300,
      maxPayloadBytes: 4096,
      rateLimitPerMinute: 20,
      retentionDays: 14
    });
    const body = Buffer.from('{"type":"build.completed"}');
    const headers = genericHeaders(body, secret, "delivery-100");
    const first = await context.app.inject({
      method: "POST", url: `/hooks/${endpoint.publicId}`, headers, payload: body
    });
    const second = await context.app.inject({
      method: "POST", url: `/hooks/${endpoint.publicId}`, headers, payload: body
    });

    expect(first.statusCode).toBe(202);
    expect(first.json()).toMatchObject({ status: "accepted", code: null });
    expect(second.statusCode).toBe(200);
    expect(second.json()).toMatchObject({ status: "duplicate", code: "DUPLICATE_DELIVERY" });
    const duplicate = context.service.getDelivery(context.owner.id, second.json().id as string)!;
    expect(duplicate.replayDetected).toBe(true);
    expect(duplicate.duplicateOf).toBe(first.json().id);
  });

  it("rejects missing signatures, modified payloads, stale timestamps, and malformed JSON", async () => {
    const secret = "integration-secret-with-entropy";
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Security cases", provider: "generic", secret, toleranceSeconds: 60,
      maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    const endpointRow = context.service.getEndpointByPublicId(endpoint.publicId)!;
    const body = Buffer.from('{"type":"deploy"}');
    const now = String(Math.floor(Date.now() / 1000));
    const tampered = context.service.processWebhook(
      endpointRow,
      Buffer.from('{"type":"deploy","admin":true}'),
      genericHeaders(body, secret, "tampered-1", now)
    );
    const missing = context.service.processWebhook(endpointRow, body, {
      "content-type": "application/json",
      "x-hookshield-delivery": "missing-1",
      "x-hookshield-timestamp": now
    });
    const expiredAt = String(Math.floor(Date.now() / 1000) - 61);
    const expired = context.service.processWebhook(
      endpointRow, body, genericHeaders(body, secret, "expired-1", expiredAt)
    );
    const malformedBody = Buffer.from("{not-json");
    const malformed = context.service.processWebhook(
      endpointRow, malformedBody, genericHeaders(malformedBody, secret, "malformed-1")
    );

    expect(tampered.rejectionCode).toBe("SIGNATURE_INVALID");
    expect(missing.rejectionCode).toBe("SIGNATURE_INVALID");
    expect(expired).toMatchObject({ status: "expired", rejectionCode: "TIMESTAMP_EXPIRED" });
    expect(malformed.rejectionCode).toBe("MALFORMED_JSON");
  });

  it("enforces payload and endpoint rate limits before cryptographic work", () => {
    const secret = "integration-secret-with-entropy";
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Ingress gates", provider: "generic", secret, toleranceSeconds: 300,
      maxPayloadBytes: 1024, rateLimitPerMinute: 1, retentionDays: 14
    });
    const endpointRow = context.service.getEndpointByPublicId(endpoint.publicId)!;
    const oversizedBody = Buffer.from(JSON.stringify({ type: "large", data: "x".repeat(1200) }));
    const oversized = context.service.processWebhook(
      endpointRow, oversizedBody, genericHeaders(oversizedBody, secret, "large-1")
    );
    const body = Buffer.from('{"type":"normal"}');
    const limited = context.service.processWebhook(
      endpointRow, body, genericHeaders(body, secret, "limited-1"), { forceRateLimit: true }
    );
    expect(oversized).toMatchObject({ httpStatus: 413, rejectionCode: "PAYLOAD_TOO_LARGE" });
    expect(limited).toMatchObject({ httpStatus: 429, rejectionCode: "RATE_LIMITED" });
  });

  it("accepts active and transitioning secret versions, then rejects an expired previous version", () => {
    const oldSecret = "old-integration-secret-with-entropy";
    const nextSecret = "next-integration-secret-with-entropy";
    const finalSecret = "final-integration-secret-with-entropy";
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Rotation", provider: "generic", secret: oldSecret, toleranceSeconds: 300,
      maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    context.service.rotateSecret(context.owner.id, endpoint.id, nextSecret, 3600);
    const endpointRow = context.service.getEndpointByPublicId(endpoint.publicId)!;
    const body = Buffer.from('{"type":"rotation.test"}');
    const oldAccepted = context.service.processWebhook(
      endpointRow, body, genericHeaders(body, oldSecret, "old-transition")
    );
    const newAccepted = context.service.processWebhook(
      endpointRow, body, genericHeaders(body, nextSecret, "new-active")
    );
    context.service.rotateSecret(context.owner.id, endpoint.id, finalSecret, 0);
    const timestamp = String(Math.floor((Date.now() + 1000) / 1000));
    const oldRejected = context.service.processWebhook(
      endpointRow,
      body,
      genericHeaders(body, nextSecret, "transition-expired", timestamp),
      { nowMs: Date.now() + 1000 }
    );

    expect(oldAccepted.status).toBe("accepted");
    expect(newAccepted.status).toBe("accepted");
    expect(oldRejected.rejectionCode).toBe("SIGNATURE_INVALID");
  });

  it("verifies GitHub over raw bytes and censors its signature header", () => {
    const secret = "github-integration-secret-with-entropy";
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "GitHub", provider: "github", secret, toleranceSeconds: 300,
      maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    const endpointRow = context.service.getEndpointByPublicId(endpoint.publicId)!;
    const body = Buffer.from('{"ref":"refs/heads/main"}');
    const result = context.service.processWebhook(endpointRow, body, {
      "content-type": "application/json",
      "x-github-event": "push",
      "x-github-delivery": "gh-delivery-1",
      "x-hub-signature-256": `sha256=${hmacSha256(secret, body)}`
    });
    const detail = context.service.getDelivery(context.owner.id, result.id)!;
    expect(result.status).toBe("accepted");
    expect(detail.headers["x-hub-signature-256"]).toBe("[REDACTED]");
    expect(detail.checks.find((check) => check.name === "Freshness window")?.status).toBe("warning");
  });
});

describe("authenticated API boundaries", () => {
  it("updates and deletes an owner-scoped endpoint without returning secret material", async () => {
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Editable endpoint", provider: "generic", secret: "editable-secret-with-enough-entropy",
      toleranceSeconds: 300, maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    const session = await login(context.owner);
    const headers = {
      cookie: session.cookie,
      origin: "http://localhost:3000",
      "x-hookshield-csrf": session.csrf
    };
    const updated = await context.app.inject({
      method: "PATCH",
      url: `/api/endpoints/${endpoint.id}`,
      headers,
      payload: { name: "Disabled endpoint", enabled: false, retentionDays: 7 }
    });
    expect(updated.statusCode).toBe(200);
    expect(updated.json()).toMatchObject({ name: "Disabled endpoint", enabled: false, retentionDays: 7 });
    expect(JSON.stringify(updated.json())).not.toContain("editable-secret-with-enough-entropy");

    const deleted = await context.app.inject({
      method: "DELETE", url: `/api/endpoints/${endpoint.id}`, headers
    });
    expect(deleted.statusCode).toBe(204);
    expect(context.service.getEndpoint(context.owner.id, endpoint.id)).toBeNull();
  });

  it("does not distinguish disabled ingress URLs from unknown endpoints", async () => {
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Disabled ingress", provider: "generic", secret: "disabled-secret-with-enough-entropy",
      toleranceSeconds: 300, maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    context.service.updateEndpoint(context.owner.id, endpoint.id, { enabled: false });
    const disabled = await context.app.inject({ method: "POST", url: `/hooks/${endpoint.publicId}`, headers: { "content-type": "application/json" }, payload: "{}" });
    const unknown = await context.app.inject({ method: "POST", url: `/hooks/${"x".repeat(43)}`, headers: { "content-type": "application/json" }, payload: "{}" });
    expect(disabled.statusCode).toBe(404);
    expect(unknown.statusCode).toBe(404);
    expect(disabled.json().error).toMatchObject({ code: "NOT_FOUND", message: "Resource not found" });
    expect(unknown.json().error).toMatchObject({ code: "NOT_FOUND", message: "Resource not found" });
  });

  it("requires CSRF for mutations and keeps owner data isolated", async () => {
    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Owner only", provider: "generic", secret: "owner-secret-with-enough-entropy",
      toleranceSeconds: 300, maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
    });
    const ownerSession = await login(context.owner);
    const otherSession = await login(context.other);
    const csrfRejected = await context.app.inject({
      method: "POST",
      url: "/api/endpoints",
      headers: { cookie: ownerSession.cookie, origin: "http://localhost:3000" },
      payload: {
        name: "Should fail", provider: "generic", secret: "another-secret-with-entropy",
        toleranceSeconds: 300, maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 14
      }
    });
    const otherRead = await context.app.inject({
      method: "GET", url: `/api/endpoints/${endpoint.id}`, headers: { cookie: otherSession.cookie }
    });
    const ownerList = await context.app.inject({
      method: "GET", url: "/api/endpoints", headers: { cookie: ownerSession.cookie }
    });

    expect(csrfRejected.statusCode).toBe(403);
    expect(csrfRejected.json()).toMatchObject({ error: { code: "CSRF_REJECTED" } });
    expect(otherRead.statusCode).toBe(404);
    expect(ownerList.json()).toHaveLength(1);
    expect(JSON.stringify(ownerList.json())).not.toContain("owner-secret-with-enough-entropy");
  });

  it("returns consistent errors and enforces retention deletion", async () => {
    const session = await login(context.owner);
    const missing = await context.app.inject({
      method: "GET", url: `/api/deliveries/${randomUUID()}`, headers: { cookie: session.cookie }
    });
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual({
      error: { code: "NOT_FOUND", message: "Resource not found", requestId: missing.json().error.requestId }
    });

    const endpoint = context.service.createEndpoint(context.owner.id, {
      name: "Retention", provider: "generic", secret: "retention-secret-with-entropy",
      toleranceSeconds: 300, maxPayloadBytes: 4096, rateLimitPerMinute: 20, retentionDays: 1
    });
    const result = context.service.simulate(context.owner.id, endpoint.id, "valid");
    context.db.connection.prepare("UPDATE deliveries SET received_at = '2020-01-01T00:00:00.000Z' WHERE id = ?")
      .run(result.id);
    expect(context.service.purgeRetention(context.owner.id)).toBe(1);
    expect(context.service.getDelivery(context.owner.id, result.id)).toBeNull();
  });
});
