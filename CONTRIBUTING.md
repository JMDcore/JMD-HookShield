# Contributing

HookShield welcomes focused fixes, tests, documentation improvements, and provider-adapter proposals. Security-sensitive behavior needs evidence, not only implementation.

## Local setup

```bash
pnpm install
pnpm demo
```

Before opening a pull request:

```bash
pnpm typecheck
pnpm test
pnpm test:e2e
pnpm build
pnpm audit
```

## Change expectations

- Keep the local demo free from mandatory external infrastructure.
- Add a failing test before or with a security fix.
- Never commit provider secrets, API keys, payloads from real people, or production delivery data.
- Preserve raw request bytes until signature verification completes.
- Treat forwarding, parsing, logging, and provider additions as threat-model changes.
- Update `docs/threat-model.md`, `DESIGN.md`, or protocol documentation when the boundary changes.
- Use Conventional Commit-style subjects such as `fix: reject expired generic signatures`.

## Pull requests

Keep changes reviewable and explain the threat or product behavior affected. Include screenshots for UI changes at desktop and mobile widths. Do not report security vulnerabilities in a public issue; follow [SECURITY.md](SECURITY.md).
