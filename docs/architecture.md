# Architecture

HookShield is deliberately local-first. The MVP separates the browser application, the webhook API, shared security primitives, shared contracts, and SQLite persistence without introducing a queue or distributed cache.

```text
Provider / simulator
        │ raw HTTP body + provider headers
        ▼
Fastify ingress ── size and rate gates
        │
        ├── provider verifier (GitHub / Stripe / Generic HMAC)
        ├── replay and idempotency decisions
        ├── encrypted secret versions (AES-256-GCM)
        └── audit + processing timeline
        │
        ▼
SQLite (WAL) ◀──── authenticated API ──── Next.js operations console
```

## Trust boundaries

1. Webhook ingress is anonymous and untrusted. Endpoint public identifiers are high-entropy capabilities, but never grant dashboard access.
2. Dashboard routes require an expiring `HttpOnly`, `SameSite=Strict` session and an origin-bound CSRF header for mutations.
3. Plaintext webhook secrets exist only while verifying or rotating. SQLite stores AES-GCM ciphertext, IV, and authentication tag; the master key is provided only through the environment.
4. HookShield does not forward to arbitrary URLs. Accepted events are processed by a controlled internal consumer.

## Key decisions

- **SQLite and in-process limits:** make the security behavior demonstrable with one command. PostgreSQL, Redis, durable queues, and distributed rate limiting are roadmap work.
- **Raw bytes first:** signatures are evaluated before parsing JSON. The persisted payload is a bounded representation with a SHA-256 digest.
- **Provider adapters:** GitHub uses `X-Hub-Signature-256`; Stripe delegates parsing and verification to the official SDK; Generic HMAC signs `timestamp.delivery-id.raw-body`.
- **Append-only evidence:** a duplicate is stored as its own delivery and points to the original, preserving the attempted replay instead of silently discarding it.
- **No secret read API:** users provide secrets during creation and rotation. Neither plaintext nor encrypted forms are returned by dashboard endpoints.

## Data model

`User` owns `Endpoint`. An endpoint owns versioned encrypted `SecretVersion` records and received `Delivery` records. A delivery has ordered `SecurityCheck` evidence and one or more `ProcessingAttempt` entries. Sensitive actions append an `AuditEvent`.

## Scale-out path

The boundary between verification and the internal consumer is intentionally explicit. A later version can move accepted processing to a durable queue, use PostgreSQL uniqueness constraints for cross-node idempotency, and use Redis for distributed rate limits without changing provider verification rules.
