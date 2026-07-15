# Testing guide

## Commands

```bash
pnpm typecheck
pnpm test
pnpm test:e2e
pnpm build
pnpm audit
```

Install Chromium once if Playwright reports that its managed browser is missing:

```bash
pnpm exec playwright install chromium
```

## Coverage map

| Control | Test level |
| --- | --- |
| Correct, missing, malformed, and incorrect HMAC | Unit + integration |
| Modified raw body | Unit + integration + E2E |
| Constant-time fixed-length comparison | Unit |
| Fresh and expired signed timestamp | Unit + integration |
| Delivery duplicate / replay evidence | Integration + E2E |
| Active, transitioning, and retired secret versions | Integration + E2E |
| AES-GCM encrypt/decrypt and authentication failure | Unit |
| Payload cap and endpoint rate limit | Integration |
| Owner separation, session, and CSRF | Integration |
| Sensitive header redaction and log-injection newline stripping | Unit + integration |
| Retention purge and controlled retry | Integration + E2E |
| Simulator product flow | E2E |
| WCAG serious/critical findings | axe + Playwright |

Tests use in-memory SQLite or the resettable local demo. They never require a provider account or public endpoint.
