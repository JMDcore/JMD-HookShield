import { describe, expect, it } from "vitest";
import {
  decryptSecret,
  encryptSecret,
  hashPassword,
  hmacSha256,
  isTimestampFresh,
  redactHeaders,
  safeCompare,
  signGeneric,
  verifyGenericSignature,
  verifyGithubSignature,
  verifyPassword
} from "./index.js";

describe("signature verification", () => {
  const secret = "test-secret-with-enough-entropy";
  const body = Buffer.from('{"event":"deployment"}');

  it("accepts a valid GitHub signature", () => {
    const signature = `sha256=${hmacSha256(secret, body)}`;
    expect(verifyGithubSignature(body, signature, secret).valid).toBe(true);
  });

  it("rejects incorrect, missing, and payload-modified signatures", () => {
    const signature = `sha256=${hmacSha256(secret, body)}`;
    expect(verifyGithubSignature(body, undefined, secret).reason).toBe("missing");
    expect(verifyGithubSignature(body, `sha256=${"0".repeat(64)}`, secret).valid).toBe(false);
    expect(verifyGithubSignature(Buffer.from("modified"), signature, secret).valid).toBe(false);
  });

  it("binds generic signatures to timestamp, delivery id, and raw payload", () => {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = signGeneric(body, timestamp, "delivery-1", secret);
    expect(verifyGenericSignature(body, signature, timestamp, "delivery-1", secret).valid).toBe(true);
    expect(verifyGenericSignature(body, signature, timestamp, "delivery-2", secret).valid).toBe(false);
    expect(verifyGenericSignature(Buffer.from("tampered"), signature, timestamp, "delivery-1", secret).valid).toBe(false);
  });

  it("uses a fixed-length constant-time primitive without throwing on length mismatch", () => {
    expect(safeCompare("same", "same")).toBe(true);
    expect(safeCompare("short", "a much longer value")).toBe(false);
  });
});

describe("freshness, encryption, password storage, and redaction", () => {
  it("accepts current timestamps and rejects expired timestamps", () => {
    const now = Date.now();
    expect(isTimestampFresh(String(Math.floor(now / 1000)), 300, now)).toBe(true);
    expect(isTimestampFresh(String(Math.floor(now / 1000) - 301), 300, now)).toBe(false);
    expect(isTimestampFresh("not-a-time", 300, now)).toBe(false);
  });

  it("encrypts and authenticates secret material", () => {
    const key = Buffer.alloc(32, 7);
    const encrypted = encryptSecret("provider-secret", key);
    expect(encrypted.ciphertext).not.toContain("provider-secret");
    expect(decryptSecret(encrypted, key)).toBe("provider-secret");
    expect(() => decryptSecret({ ...encrypted, authTag: Buffer.alloc(16).toString("base64") }, key)).toThrow();
  });

  it("hashes passwords and verifies them", () => {
    const stored = hashPassword("a very long demo password");
    expect(stored).not.toContain("a very long demo password");
    expect(verifyPassword("a very long demo password", stored)).toBe(true);
    expect(verifyPassword("wrong password", stored)).toBe(false);
  });

  it("redacts signature and session headers while removing log injection", () => {
    const redacted = redactHeaders({
      Authorization: "Bearer secret",
      "X-Hub-Signature-256": "sha256=secret",
      "X-Request-Name": "safe\nforged"
    });
    expect(redacted.authorization).toBe("[REDACTED]");
    expect(redacted["x-hub-signature-256"]).toBe("[REDACTED]");
    expect(redacted["x-request-name"]).toBe("safe forged");
  });
});
