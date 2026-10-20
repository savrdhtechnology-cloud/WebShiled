import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

function key() {
  const secret = process.env.WEBSHIELD_ENCRYPTION_KEY || "";
  if (secret.length < 32) throw new Error("Secure credential storage is not configured.");
  return createHash("sha256").update(secret).digest();
}

function b64(value: Buffer) {
  return value.toString("base64url");
}

export function encryptSecret(value: string) {
  if (!value.trim()) throw new Error("A provider token is required.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", b64(iv), b64(tag), b64(ciphertext)].join(".");
}

export function decryptSecret(value: string) {
  const [version, ivRaw, tagRaw, ciphertextRaw] = value.split(".");
  if (version !== "v1" || !ivRaw || !tagRaw || !ciphertextRaw) throw new Error("Stored provider credential is invalid.");
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(ivRaw, "base64url"));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextRaw, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

export function secretHint(value: string) {
  const clean = value.trim();
  if (clean.length < 10) return "••••••";
  return clean.slice(0, 6) + "••••" + clean.slice(-4);
}
