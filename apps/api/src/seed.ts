import { randomUUID } from "node:crypto";
import { hashPassword } from "@hookshield/security";
import { buildApp } from "./app.js";

const { app, db, service, config } = await buildApp();

if (!config.demoMode) {
  throw new Error("Demo seed is only available when HOOKSHIELD_DEMO_MODE=true");
}

db.connection.exec(`
  DELETE FROM audit_events;
  DELETE FROM processing_attempts;
  DELETE FROM security_checks;
  DELETE FROM deliveries;
  DELETE FROM secret_versions;
  DELETE FROM endpoints;
  DELETE FROM sessions;
  DELETE FROM users;
`);

const demoUser = {
  id: randomUUID(),
  email: "demo@hookshield.local",
  name: "José Miguel Díaz"
};
db.connection.prepare(`
  INSERT INTO users (id, email, name, password_hash, created_at)
  VALUES (?, ?, ?, ?, ?)
`).run(
  demoUser.id,
  demoUser.email,
  demoUser.name,
  hashPassword("HookShield-demo-2026!"),
  new Date().toISOString()
);

const github = service.createEndpoint(demoUser.id, {
  name: "GitHub releases",
  provider: "github",
  secret: "demo-github-secret-not-for-production",
  toleranceSeconds: 300,
  maxPayloadBytes: 262_144,
  rateLimitPerMinute: 120,
  retentionDays: 14
});
const stripe = service.createEndpoint(demoUser.id, {
  name: "Stripe sandbox",
  provider: "stripe",
  secret: "whsec_demo_only_hookshield_2026",
  toleranceSeconds: 300,
  maxPayloadBytes: 262_144,
  rateLimitPerMinute: 120,
  retentionDays: 14
});
const generic = service.createEndpoint(demoUser.id, {
  name: "Deployment events",
  provider: "generic",
  secret: "demo-generic-secret-not-for-production",
  toleranceSeconds: 300,
  maxPayloadBytes: 32_768,
  rateLimitPerMinute: 120,
  retentionDays: 14
});

service.simulate(demoUser.id, github.id, "valid");
service.simulate(demoUser.id, stripe.id, "valid");
service.simulate(demoUser.id, generic.id, "valid");
service.simulate(demoUser.id, generic.id, "invalid_signature");
service.simulate(demoUser.id, github.id, "tampered_payload");
service.simulate(demoUser.id, generic.id, "expired_timestamp");
service.simulate(demoUser.id, generic.id, "duplicate");
service.simulate(demoUser.id, generic.id, "rate_limited");

await app.close();
process.stdout.write("HookShield demo database ready.\n");
