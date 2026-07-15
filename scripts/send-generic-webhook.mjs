import { createHmac, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

const [targetValue, payloadPath] = process.argv.slice(2);
const secret = process.env.HOOKSHIELD_WEBHOOK_SECRET;

if (!targetValue || !payloadPath || !secret) {
  process.stderr.write(
    "Usage: HOOKSHIELD_WEBHOOK_SECRET=<test-secret> pnpm send:generic <localhost-url> <payload.json>\n"
  );
  process.exit(2);
}
if (secret.length < 16) {
  process.stderr.write("HOOKSHIELD_WEBHOOK_SECRET must contain at least 16 characters.\n");
  process.exit(2);
}

const target = new URL(targetValue);
if (!["localhost", "127.0.0.1", "::1"].includes(target.hostname)) {
  process.stderr.write("The bundled sender is intentionally restricted to localhost targets.\n");
  process.exit(2);
}
if (!["http:", "https:"].includes(target.protocol)) {
  process.stderr.write("The target must use HTTP or HTTPS.\n");
  process.exit(2);
}

const rawBody = await readFile(payloadPath);
JSON.parse(rawBody.toString("utf8"));
const timestamp = String(Math.floor(Date.now() / 1000));
const deliveryId = `cli_${randomBytes(12).toString("hex")}`;
const signedBytes = Buffer.concat([
  Buffer.from(`${timestamp}.${deliveryId}.`, "utf8"),
  rawBody
]);
const signature = createHmac("sha256", secret).update(signedBytes).digest("hex");

const response = await fetch(target, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-hookshield-timestamp": timestamp,
    "x-hookshield-delivery": deliveryId,
    "x-hookshield-signature": `sha256=${signature}`
  },
  body: rawBody
});

const responseText = await response.text();
process.stdout.write(`${response.status} ${response.statusText}\n${responseText}\n`);
process.exitCode = response.ok ? 0 : 1;
