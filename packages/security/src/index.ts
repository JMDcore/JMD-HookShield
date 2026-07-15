import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";

export interface EncryptedSecret {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export interface VerificationResult {
  valid: boolean;
  reason: "valid" | "missing" | "malformed" | "mismatch";
}

export function parseMasterKey(value: string | undefined): Buffer {
  if (!value) throw new Error("HOOKSHIELD_MASTER_KEY is required");
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== 32) {
    throw new Error("HOOKSHIELD_MASTER_KEY must be a base64-encoded 32-byte key");
  }
  return decoded;
}

export function encryptSecret(secret: string, key: Buffer): EncryptedSecret {
  if (key.length !== 32) throw new Error("AES-256-GCM requires a 32-byte key");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  };
}

export function decryptSecret(value: EncryptedSecret, key: Buffer): string {
  if (key.length !== 32) throw new Error("AES-256-GCM requires a 32-byte key");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(value.iv, "base64"));
  decipher.setAuthTag(Buffer.from(value.authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(value.ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8");
}

export function safeCompare(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  const leftDigest = createHash("sha256").update(leftBytes).digest();
  const rightDigest = createHash("sha256").update(rightBytes).digest();
  return timingSafeEqual(leftDigest, rightDigest) && leftBytes.length === rightBytes.length;
}

export function hmacSha256(secret: string, data: Buffer | string): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function verifyGithubSignature(
  rawBody: Buffer,
  signature: string | undefined,
  secret: string
): VerificationResult {
  if (!signature) return { valid: false, reason: "missing" };
  if (!/^sha256=[a-f0-9]{64}$/i.test(signature)) return { valid: false, reason: "malformed" };
  const expected = `sha256=${hmacSha256(secret, rawBody)}`;
  return safeCompare(expected.toLowerCase(), signature.toLowerCase())
    ? { valid: true, reason: "valid" }
    : { valid: false, reason: "mismatch" };
}

export function genericSigningInput(timestamp: string, deliveryId: string, rawBody: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`${timestamp}.${deliveryId}.`, "utf8"),
    rawBody
  ]);
}

export function signGeneric(
  rawBody: Buffer,
  timestamp: string,
  deliveryId: string,
  secret: string
): string {
  return `sha256=${hmacSha256(secret, genericSigningInput(timestamp, deliveryId, rawBody))}`;
}

export function verifyGenericSignature(
  rawBody: Buffer,
  signature: string | undefined,
  timestamp: string,
  deliveryId: string,
  secret: string
): VerificationResult {
  if (!signature) return { valid: false, reason: "missing" };
  if (!/^sha256=[a-f0-9]{64}$/i.test(signature)) return { valid: false, reason: "malformed" };
  const expected = signGeneric(rawBody, timestamp, deliveryId, secret);
  return safeCompare(expected.toLowerCase(), signature.toLowerCase())
    ? { valid: true, reason: "valid" }
    : { valid: false, reason: "mismatch" };
}

export function isTimestampFresh(
  timestampSeconds: string,
  toleranceSeconds: number,
  nowMs = Date.now()
): boolean {
  if (!/^\d{10}$/.test(timestampSeconds)) return false;
  const timestamp = Number(timestampSeconds) * 1000;
  return Number.isSafeInteger(timestamp) && Math.abs(nowMs - timestamp) <= toleranceSeconds * 1000;
}

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-hub-signature-256",
  "stripe-signature",
  "x-hookshield-signature"
]);

export function redactHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => {
      const normalized = name.toLowerCase();
      if (SENSITIVE_HEADERS.has(normalized)) return [normalized, "[REDACTED]"];
      const rendered = Array.isArray(value) ? value.join(", ") : String(value ?? "");
      return [normalized, rendered.replace(/[\r\n]/g, " ").slice(0, 2048)];
    })
  );
}

export function hashPassword(password: string, salt = randomBytes(16)): string {
  const derived = scryptSync(password, salt, 64);
  return `scrypt:${salt.toString("base64")}:${derived.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [algorithm, saltValue, hashValue] = stored.split(":");
  if (algorithm !== "scrypt" || !saltValue || !hashValue) return false;
  const expected = Buffer.from(hashValue, "base64");
  const actual = scryptSync(password, Buffer.from(saltValue, "base64"), expected.length);
  return timingSafeEqual(actual, expected);
}

export function sha256(rawBody: Buffer): string {
  return createHash("sha256").update(rawBody).digest("hex");
}
