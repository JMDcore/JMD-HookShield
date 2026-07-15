# Threat model

HookShield is a professional portfolio MVP, not a production security gateway. This model uses STRIDE-style categories and documents the controls that are implemented locally.

| Threat | Primary control | Residual limitation |
| --- | --- | --- |
| Forged or modified webhook | HMAC-SHA256 / official Stripe verifier over raw bytes; constant-time comparison | A compromised provider secret can still forge events |
| Replay and duplicate delivery | Signed timestamp where the provider supports it; delivery identifier idempotency; append-only evidence | GitHub does not sign a timestamp, so freshness cannot be proven from its standard signature alone |
| Secret theft at rest | AES-256-GCM envelope encrypted by an environment-only master key; no secret read endpoint | A process or host compromise can access key material in memory |
| Rotation race | Active and previous versions accepted during a bounded transition window | Operators must complete provider-side rotation inside the window |
| Endpoint enumeration | 256-bit public identifiers and consistent not-found responses | URL disclosure still permits delivery attempts, mitigated by rate limits |
| Brute force / flooding | Global and per-endpoint limits plus payload caps | In-memory counters are single-node only |
| Cross-user data access | Owner predicates on every dashboard query and mutation | The demo ships with one synthetic user |
| CSRF and session theft | Strict `HttpOnly` cookie, origin checks, CSRF header, expiry; `Secure` in production | Local HTTP cannot set `Secure` cookies |
| XSS / sensitive headers | CSP, React escaping, structured header redaction, no `dangerouslySetInnerHTML` | Payloads should still be treated as hostile when adding renderers |
| Log injection / data leakage | Structured logs, newline scrubbing, allowlisted metadata, header redaction | Payload persistence can contain sensitive business data |
| Excessive retention | Per-endpoint retention setting and explicit purge operation | Scheduled purge is process-local in the MVP |
| Malformed JSON / unsafe deserialization | Verify bytes first; bounded `JSON.parse`; no dynamic evaluation | Deep JSON is displayed as text rather than recursively executed |
| Vulnerable dependencies | Lockfile, Dependabot, CI audit, CodeQL | A clean scan is point-in-time evidence only |

## Out of scope

- Arbitrary webhook forwarding, to avoid introducing SSRF into the MVP.
- Multi-region replay guarantees or horizontally distributed rate limits.
- Hardware-backed key management and per-tenant key wrapping.
- Claims of production readiness or formal cryptographic verification.
