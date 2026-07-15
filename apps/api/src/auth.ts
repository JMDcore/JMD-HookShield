import { randomBytes, randomUUID } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { AppConfig } from "./config.js";
import type { HookShieldDatabase } from "@hookshield/database";
import { verifyPassword } from "@hookshield/security";

const SESSION_COOKIE = "hookshield_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
}

interface SessionUserRow {
  session_id: string;
  csrf_token: string;
  expires_at: string;
  id: string;
  email: string;
  name: string;
}

export function authenticateUser(
  db: HookShieldDatabase,
  email: string,
  password: string
): Omit<UserRow, "password_hash"> | null {
  const user = db.connection.prepare(
    "SELECT id, email, name, password_hash FROM users WHERE email = ?"
  ).get(email.toLowerCase()) as UserRow | undefined;
  if (!user || !verifyPassword(password, user.password_hash)) return null;
  return { id: user.id, email: user.email, name: user.name };
}

export function createSession(
  db: HookShieldDatabase,
  config: AppConfig,
  reply: FastifyReply,
  user: { id: string; email: string; name: string }
): { user: typeof user; csrfToken: string } {
  const sessionId = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(32).toString("base64url");
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_MS);
  db.connection.prepare(`
    INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, user.id, csrfToken, expires.toISOString(), now.toISOString());
  reply.setCookie(SESSION_COOKIE, sessionId, {
    path: "/",
    httpOnly: true,
    sameSite: "strict",
    secure: config.secureCookies,
    expires,
    signed: false
  });
  return { user, csrfToken };
}

export function deleteSession(db: HookShieldDatabase, request: FastifyRequest, reply: FastifyReply): void {
  const sessionId = request.cookies[SESSION_COOKIE];
  if (sessionId) db.connection.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
  reply.clearCookie(SESSION_COOKIE, { path: "/" });
}

export function makeAuthGuards(db: HookShieldDatabase, config: AppConfig) {
  async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const sessionId = request.cookies[SESSION_COOKIE];
    if (!sessionId) {
      await reply.code(401).send({
        error: { code: "AUTH_REQUIRED", message: "Authentication is required", requestId: request.id }
      });
      return;
    }
    const row = db.connection.prepare(`
      SELECT s.id AS session_id, s.csrf_token, s.expires_at, u.id, u.email, u.name
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ? AND s.expires_at > ?
    `).get(sessionId, new Date().toISOString()) as SessionUserRow | undefined;
    if (!row) {
      reply.clearCookie(SESSION_COOKIE, { path: "/" });
      await reply.code(401).send({
        error: { code: "AUTH_REQUIRED", message: "Authentication is required", requestId: request.id }
      });
      return;
    }
    request.authUser = {
      id: row.id,
      email: row.email,
      name: row.name,
      csrfToken: row.csrf_token,
      sessionId: row.session_id
    };
  }

  async function requireCsrf(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (!request.authUser) return;
    const token = request.headers["x-hookshield-csrf"];
    const origin = request.headers.origin;
    if (typeof token !== "string" || token !== request.authUser.csrfToken || origin !== config.webOrigin) {
      await reply.code(403).send({
        error: { code: "CSRF_REJECTED", message: "The request failed CSRF validation", requestId: request.id }
      });
    }
  }

  return { requireAuth, requireCsrf };
}

export function appendAudit(
  db: HookShieldDatabase,
  input: {
    userId?: string | null;
    endpointId?: string | null;
    deliveryId?: string | null;
    action: string;
    outcome: string;
    metadata?: Record<string, unknown>;
  }
): void {
  db.connection.prepare(`
    INSERT INTO audit_events
      (id, user_id, endpoint_id, delivery_id, action, outcome, metadata_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    randomUUID(),
    input.userId ?? null,
    input.endpointId ?? null,
    input.deliveryId ?? null,
    input.action,
    input.outcome,
    JSON.stringify(input.metadata ?? {}),
    new Date().toISOString()
  );
}
