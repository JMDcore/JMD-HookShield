import type { FastifyRequest } from "fastify";

declare module "fastify" {
  interface FastifyRequest {
    rawBody?: Buffer | string;
    authUser?: {
      id: string;
      email: string;
      name: string;
      csrfToken: string;
      sessionId: string;
    };
  }
}

export type AuthenticatedRequest = FastifyRequest & {
  authUser: NonNullable<FastifyRequest["authUser"]>;
};
