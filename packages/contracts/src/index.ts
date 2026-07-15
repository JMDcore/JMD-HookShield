import { z } from "zod";

export const providerSchema = z.enum(["github", "stripe", "generic"]);
export type Provider = z.infer<typeof providerSchema>;

export const deliveryStatusSchema = z.enum([
  "accepted",
  "rejected",
  "duplicate",
  "expired",
  "failed"
]);
export type DeliveryStatus = z.infer<typeof deliveryStatusSchema>;

export const checkStatusSchema = z.enum(["passed", "failed", "warning", "skipped"]);
export type CheckStatus = z.infer<typeof checkStatusSchema>;

export const createEndpointSchema = z.object({
  name: z.string().trim().min(2).max(80),
  provider: providerSchema,
  secret: z.string().min(16).max(512),
  toleranceSeconds: z.number().int().min(30).max(900).default(300),
  maxPayloadBytes: z.number().int().min(1024).max(1_048_576).default(262_144),
  rateLimitPerMinute: z.number().int().min(1).max(600).default(60),
  retentionDays: z.number().int().min(1).max(90).default(14)
});
export type CreateEndpointInput = z.infer<typeof createEndpointSchema>;

export const updateEndpointSchema = z.object({
  name: z.string().trim().min(2).max(80).optional(),
  enabled: z.boolean().optional(),
  toleranceSeconds: z.number().int().min(30).max(900).optional(),
  maxPayloadBytes: z.number().int().min(1024).max(1_048_576).optional(),
  rateLimitPerMinute: z.number().int().min(1).max(600).optional(),
  retentionDays: z.number().int().min(1).max(90).optional()
});

export const rotateSecretSchema = z.object({
  secret: z.string().min(16).max(512),
  transitionSeconds: z.number().int().min(0).max(86_400).default(3600)
});

export const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(200)
});

export const simulatorScenarioSchema = z.enum([
  "valid",
  "invalid_signature",
  "tampered_payload",
  "expired_timestamp",
  "duplicate",
  "replay",
  "oversized_payload",
  "rate_limited",
  "valid_after_rotation"
]);

export const simulatorRequestSchema = z.object({
  endpointId: z.string().uuid(),
  scenario: simulatorScenarioSchema
});
export type SimulatorScenario = z.infer<typeof simulatorScenarioSchema>;

export interface EndpointSummary {
  id: string;
  publicId: string;
  name: string;
  provider: Provider;
  enabled: boolean;
  toleranceSeconds: number;
  maxPayloadBytes: number;
  rateLimitPerMinute: number;
  retentionDays: number;
  secretVersion: number;
  ingestUrl: string;
  createdAt: string;
}

export interface SecurityCheckView {
  id: string;
  name: string;
  status: CheckStatus;
  detail: string;
  sortOrder: number;
}

export interface TimelineEntry {
  id: string;
  attemptNumber: number;
  status: string;
  detail: string;
  startedAt: string;
  completedAt: string | null;
}

export interface DeliveryView {
  id: string;
  endpointId: string;
  endpointName: string;
  provider: Provider;
  providerDeliveryId: string | null;
  eventType: string;
  status: DeliveryStatus;
  httpStatus: number;
  payload: string;
  payloadSha256: string;
  payloadBytes: number;
  headers: Record<string, string>;
  receivedAt: string;
  processedAt: string | null;
  signatureValid: boolean | null;
  replayDetected: boolean;
  rejectionCode: string | null;
  duplicateOf: string | null;
  checks: SecurityCheckView[];
  timeline: TimelineEntry[];
}

export interface DashboardSummary {
  total24h: number;
  accepted24h: number;
  rejected24h: number;
  duplicate24h: number;
  acceptanceRate: number;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    requestId: string;
  };
}
