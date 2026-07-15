import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import {
  createEndpointSchema,
  deliveryStatusSchema,
  loginSchema,
  rotateSecretSchema,
  simulatorRequestSchema,
  updateEndpointSchema
} from "@hookshield/contracts";
import { HookShieldDatabase } from "@hookshield/database";
import { loadConfig, type AppConfig } from "./config.js";
import {
  appendAudit,
  authenticateUser,
  createSession,
  deleteSession,
  makeAuthGuards
} from "./auth.js";
import { HookShieldService } from "./service.js";
import "./types.js";

function errorBody(requestId: string, code: string, message: string) {
  return { error: { code, message, requestId } };
}

export async function buildApp(overrides: Partial<AppConfig> = {}): Promise<{
  app: FastifyInstance;
  db: HookShieldDatabase;
  service: HookShieldService;
  config: AppConfig;
}> {
  const config = loadConfig(overrides);
  const db = new HookShieldDatabase(config.databasePath);
  const service = new HookShieldService(db, config.masterKey, `http://localhost:${config.port}`);
  const app = Fastify({
    logger: process.env.NODE_ENV === "test" ? false : {
      level: process.env.LOG_LEVEL ?? "info",
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "req.headers.x-hub-signature-256",
          "req.headers.stripe-signature",
          "req.headers.x-hookshield-signature",
          "body.secret",
          "res.headers.set-cookie"
        ],
        censor: "[REDACTED]"
      }
    },
    bodyLimit: 2_097_152,
    requestIdHeader: "x-request-id",
    genReqId: () => crypto.randomUUID()
  });

  await app.register(cookie);
  await app.register(cors, {
    origin: config.webOrigin,
    credentials: true,
    methods: ["GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["content-type", "x-hookshield-csrf", "x-request-id"]
  });
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginResourcePolicy: { policy: "same-site" }
  });
  await app.register(rateLimit, {
    global: true,
    max: 600,
    timeWindow: "1 minute",
    allowList: (request) => request.url.startsWith("/hooks/")
  });

  const { requireAuth, requireCsrf } = makeAuthGuards(db, config);
  const protectedMutation = { preHandler: [requireAuth, requireCsrf] };
  const protectedRead = { preHandler: [requireAuth] };

  app.addHook("onClose", async () => db.close());
  app.addHook("onSend", async (_request, reply) => {
    reply.header("cache-control", "no-store");
    reply.header("x-content-type-options", "nosniff");
  });

  app.setErrorHandler(async (error, request, reply) => {
    if (error instanceof ZodError) {
      await reply.code(400).send(errorBody(request.id, "VALIDATION_ERROR", "The request payload is invalid"));
      return;
    }
    if ((error as { code?: string }).code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      await reply.code(413).send(errorBody(request.id, "PAYLOAD_TOO_LARGE", "The request body exceeds the server limit"));
      return;
    }
    request.log.error({ err: error }, "request failed");
    await reply.code(500).send(errorBody(request.id, "INTERNAL_ERROR", "The request could not be completed"));
  });

  app.get("/health", async () => ({ status: "ok", mode: config.demoMode ? "demo" : "standard" }));

  app.post("/api/auth/login", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const input = loginSchema.parse(request.body);
    const user = authenticateUser(db, input.email, input.password);
    if (!user) {
      appendAudit(db, {
        action: "auth.login", outcome: "rejected", metadata: { email: input.email.toLowerCase() }
      });
      return reply.code(401).send(errorBody(request.id, "INVALID_CREDENTIALS", "Email or password is incorrect"));
    }
    const session = createSession(db, config, reply, user);
    appendAudit(db, { userId: user.id, action: "auth.login", outcome: "success" });
    return session;
  });

  app.post("/api/auth/demo", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    if (!config.demoMode) {
      return reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
    }
    const user = db.connection.prepare(
      "SELECT id, email, name FROM users WHERE email = 'demo@hookshield.local'"
    ).get() as { id: string; email: string; name: string } | undefined;
    if (!user) return reply.code(503).send(errorBody(request.id, "DEMO_NOT_READY", "Demo data is not ready"));
    return createSession(db, config, reply, user);
  });

  app.get("/api/auth/me", protectedRead, async (request) => ({
    user: {
      id: request.authUser!.id,
      email: request.authUser!.email,
      name: request.authUser!.name
    },
    csrfToken: request.authUser!.csrfToken,
    demoMode: config.demoMode
  }));

  app.post("/api/auth/logout", protectedMutation, async (request, reply) => {
    deleteSession(db, request, reply);
    return { ok: true };
  });

  app.get("/api/endpoints", protectedRead, async (request) =>
    service.listEndpoints(request.authUser!.id)
  );

  app.post("/api/endpoints", protectedMutation, async (request, reply) => {
    const input = createEndpointSchema.parse(request.body);
    return reply.code(201).send(service.createEndpoint(request.authUser!.id, input));
  });

  app.patch<{ Params: { id: string } }>("/api/endpoints/:id", protectedMutation, async (request, reply) => {
    const input = updateEndpointSchema.parse(request.body);
    const endpoint = service.updateEndpoint(request.authUser!.id, request.params.id, input);
    return endpoint ?? reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
  });

  app.delete<{ Params: { id: string } }>("/api/endpoints/:id", protectedMutation, async (request, reply) => {
    const deleted = service.deleteEndpoint(request.authUser!.id, request.params.id);
    return deleted ? reply.code(204).send() : reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
  });

  app.post<{ Params: { id: string } }>("/api/endpoints/:id/rotate", protectedMutation, async (request, reply) => {
    const input = rotateSecretSchema.parse(request.body);
    const endpoint = service.rotateSecret(
      request.authUser!.id, request.params.id, input.secret, input.transitionSeconds
    );
    return endpoint ?? reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
  });

  app.get("/api/dashboard", protectedRead, async (request) =>
    service.dashboardSummary(request.authUser!.id)
  );

  app.get<{ Querystring: { endpointId?: string; status?: string; query?: string } }>(
    "/api/deliveries", protectedRead, async (request) => {
      const status = request.query.status ? deliveryStatusSchema.parse(request.query.status) : undefined;
      return service.listDeliveries(request.authUser!.id, {
        endpointId: request.query.endpointId,
        status,
        query: request.query.query
      });
    }
  );

  app.get<{ Params: { id: string } }>("/api/deliveries/:id", protectedRead, async (request, reply) => {
    const delivery = service.getDelivery(request.authUser!.id, request.params.id);
    return delivery ?? reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
  });

  app.post<{ Params: { id: string } }>("/api/deliveries/:id/retry", protectedMutation, async (request, reply) => {
    const delivery = service.retryDelivery(request.authUser!.id, request.params.id);
    return delivery ?? reply.code(409).send(errorBody(
      request.id, "RETRY_NOT_ALLOWED", "Only accepted or failed deliveries may be retried, up to two times"
    ));
  });

  app.post("/api/simulator", protectedMutation, async (request, reply) => {
    const input = simulatorRequestSchema.parse(request.body);
    try {
      const result = service.simulate(request.authUser!.id, input.endpointId, input.scenario);
      return reply.code(result.httpStatus >= 400 ? 200 : 201).send(result);
    } catch (error) {
      if (error instanceof Error && error.message === "ENDPOINT_NOT_FOUND") {
        return reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
      }
      throw error;
    }
  });

  app.get("/api/audit/export", protectedRead, async (request, reply) => {
    reply.header("content-disposition", `attachment; filename=hookshield-audit-${new Date().toISOString().slice(0, 10)}.json`);
    return service.exportAudit(request.authUser!.id);
  });

  app.post("/api/retention/purge", protectedMutation, async (request) => ({
    deleted: service.purgeRetention(request.authUser!.id)
  }));

  await app.register(async (webhookApp) => {
    webhookApp.removeAllContentTypeParsers();
    webhookApp.addContentTypeParser(
      "*",
      { parseAs: "buffer", bodyLimit: 2_097_152 },
      (_request, body, done) => done(null, body)
    );
    webhookApp.post<{ Params: { publicId: string } }>(
      "/hooks/:publicId",
      { bodyLimit: 2_097_152 },
      async (request, reply) => {
        const endpoint = service.getEndpointByPublicId(request.params.publicId);
        if (!endpoint || !endpoint.enabled) {
          return reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
        }
        const capturedBody = Buffer.isBuffer(request.body)
          ? request.body
          : Buffer.from(String(request.body ?? ""), "utf8");
        const result = service.processWebhook(endpoint, capturedBody, request.headers);
        return reply.code(result.httpStatus).send({
          id: result.id,
          status: result.status,
          code: result.rejectionCode
        });
      }
    );
  });

  app.setNotFoundHandler(async (request, reply) => {
    await reply.code(404).send(errorBody(request.id, "NOT_FOUND", "Resource not found"));
  });

  return { app, db, service, config };
}
