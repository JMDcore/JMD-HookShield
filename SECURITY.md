# Security policy

## Supported version

HookShield is a portfolio MVP under active development. Security fixes are applied to the latest `main` branch only. It is not represented as a production security gateway.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Email **jmdcore.dev@gmail.com** with:

- A concise description and affected component.
- Reproduction steps using synthetic data.
- Expected impact and any suggested mitigation.
- Whether you believe active exploitation is occurring.

You should receive an acknowledgement within five business days. Please allow reasonable time to validate and fix the issue before public disclosure. Do not access data that is not yours, degrade third-party systems, or test against endpoints without explicit authorisation.

## Scope notes

Particularly useful reports include signature bypass, replay/idempotency failure, secret disclosure, cross-user access, CSRF/session weaknesses, unsafe payload handling, log leakage, and dependency compromise. The documented single-node limitations and absence of arbitrary forwarding are design constraints, not undisclosed vulnerabilities.
