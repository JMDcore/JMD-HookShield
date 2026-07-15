# Demo and simulator

## Start

```bash
pnpm install
pnpm demo
```

`pnpm demo` creates `.data/hookshield.db`, inserts one synthetic local user and three endpoints, records representative deliveries, then starts the API on port 8787 and the web console on port 3000. It does not contact GitHub, Stripe, or any other service.

Demo mode sets a deterministic test-only master key in the child processes and resets the local database on each start. Do not reuse demo keys or seeded webhook secrets outside this repository.

## Scenarios

| Scenario | Expected decision | Evidence |
| --- | --- | --- |
| Valid webhook | Accepted | Signature, freshness (where available), JSON, and delivery ID pass |
| Incorrect signature | Rejected | No usable secret version matches |
| Tampered payload | Rejected | Signature was made over different raw bytes |
| Expired timestamp | Expired | Signed timestamp is outside endpoint tolerance |
| Duplicate delivery | Duplicate | Provider delivery ID points to an earlier accepted event |
| Replay attempt | Expired / duplicate | Freshness or idempotency stops reuse |
| Oversized payload | Rejected · 413 | Size gate stops further work |
| Rate limit exceeded | Rejected · 429 | Endpoint minute window is exhausted |
| Valid after rotation | Accepted | A new secret version signs the event |

GitHub's standard webhook signature has no signed timestamp. The simulator disables timestamp-only GitHub cases and explains why.

## Data safety

- All people, events, identifiers, and payloads are synthetic.
- Plaintext secrets are accepted only by create/rotate operations and are never returned.
- Displayed signature, cookie, authorisation, and API-key headers are replaced with `[REDACTED]`.
- Oversized payload evidence is truncated while its full SHA-256 and byte length are recorded.
