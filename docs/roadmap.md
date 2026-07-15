# Roadmap

## MVP — implemented

- Local secure authentication and owner scoping.
- GitHub, Stripe, and Generic HMAC adapters over raw request bytes.
- Freshness where the provider signs a timestamp; delivery ID idempotency.
- AES-GCM secret storage and bounded version transition.
- Global/API and per-endpoint rate policy, payload caps, redaction, retention, audit export.
- Delivery inbox, inspector, security checks, formatted payload, headers, timeline, simulator, and controlled retry.
- SQLite demo, unit/integration/E2E/accessibility tests, CI, CodeQL, and dependency updates.

## Next

- PostgreSQL constraints for cross-process idempotency.
- Redis-backed distributed rate windows.
- Durable worker queue with backoff, dead-letter evidence, and consumer contracts.
- KMS-backed envelope encryption and tenant-specific data keys.
- OIDC/SSO, role-based access, and session administration.
- Scheduled retention with legal-hold exceptions.
- OpenTelemetry traces and redaction-aware metrics.

## Later, only with a dedicated threat review

- Sandboxed destinations with DNS/IP revalidation, private-network denial, egress allowlists, and SSRF tests.
- Team workspaces and multi-region replay coordination.
- Pluggable provider adapters with signed adapter manifests.
- Compliance-oriented evidence bundles and external SIEM export.
