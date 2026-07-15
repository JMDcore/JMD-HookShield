# Optional provider testing

These paths are optional. Use only sandbox accounts, repositories you own, or systems where you have explicit permission. The built-in simulator is sufficient to evaluate the MVP without network exposure.

## GitHub CLI forwarding

GitHub documents a first-party CLI extension for forwarding repository or organisation webhooks directly to a local URL. It is for development only, not production.

1. Create a GitHub endpoint in HookShield and provide a test secret that you control.
2. Copy its local ingest URL from the endpoint data (format: `http://localhost:8787/hooks/<public-id>`).
3. Authenticate GitHub CLI and install the forwarding extension:

   ```bash
   gh auth login
   gh extension install cli/gh-webhook
   ```

4. Forward events from an authorised test repository:

   ```bash
   gh webhook forward \
     --repo=JMDcore/AUTHORISED_TEST_REPOSITORY \
     --events=push,pull_request \
     --url=http://localhost:8787/hooks/YOUR_PUBLIC_ENDPOINT_ID
   ```

The extension manages forwarding; no public HookShield port is required. Configure the same test secret on the GitHub webhook if the chosen forwarding flow requests it. See GitHub's official [CLI forwarding guide](https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/using-the-github-cli-to-forward-webhooks-for-testing) and [signature validation guidance](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## Stripe CLI sandbox

1. Create a Stripe endpoint in HookShield.
2. Start the Stripe CLI in sandbox mode and forward to the local ingest URL:

   ```bash
   stripe login
   stripe listen \
     --events payment_intent.succeeded \
     --forward-to localhost:8787/hooks/YOUR_PUBLIC_ENDPOINT_ID
   ```

3. Stripe CLI prints a `whsec_…` signing secret. Rotate or recreate the HookShield endpoint using that value. Do not commit it.
4. In another terminal, trigger a sandbox event:

   ```bash
   stripe trigger payment_intent.succeeded
   ```

Stripe documents `listen --forward-to` in its official [CLI guide](https://docs.stripe.com/stripe-cli/use-cli) and the trigger in [sandbox event testing](https://docs.stripe.com/stripe-cli/triggers). HookShield delegates signature construction and validation to the official Stripe Node SDK and applies the endpoint freshness tolerance separately to the signed timestamp.

## Generic HMAC CLI

This path stays entirely on localhost.

```bash
export HOOKSHIELD_WEBHOOK_SECRET='your-local-test-secret-16-chars-minimum'
pnpm send:generic \
  http://localhost:8787/hooks/YOUR_PUBLIC_ENDPOINT_ID \
  scripts/examples/deployment.json
unset HOOKSHIELD_WEBHOOK_SECRET
```

The sender reads the secret from the environment to avoid placing it in the command arguments, creates a unique delivery ID, signs the exact file bytes, and sends the three headers defined in [the Generic HMAC protocol](generic-hmac.md).

## Clean-up

Stop forwarding processes with `Ctrl+C`, remove temporary provider webhooks, unset shell variables, and delete any sandbox secrets that are no longer needed. Never reuse the demo or documentation values in a real system.
