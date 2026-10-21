// Verifies GitHub Actions OIDC tokens so the scheduled monitoring workflow can
// call /api/cron/monitor without any shared secret. GitHub signs a short-lived
// JWT for the workflow run; we check the signature against GitHub's published
// keys and accept only tokens issued to the WebShield repository's main branch.
//
// No Next/Node-only imports beyond node:crypto so the logic can be unit tested.

import { createPublicKey, verify } from "node:crypto";

export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const MONITOR_AUDIENCE = "webshield-monitor";
const DEFAULT_REPOSITORIES = ["savrdhtechnology-cloud/webshiled"];

export type Jwk = { kid?: string; kty?: string; n?: string; e?: string; alg?: string; use?: string };
export type OidcClaims = Record<string, unknown> & { iss?: string; aud?: string | string[]; exp?: number; nbf?: number; iat?: number; repository?: string; ref?: string };

function base64url(value: string) {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function looksLikeJwt(value: string) {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}

export function allowedRepositories() {
  const raw = process.env.WEBSHIELD_MONITOR_REPOSITORIES || "";
  const list = raw.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
  return list.length ? list : DEFAULT_REPOSITORIES;
}

/** Pure verification given a key set. Throws with a reason when invalid. */
export function verifyOidcToken(token: string, keys: Jwk[], options: { repositories: string[]; audience?: string; now?: number }) {
  if (!looksLikeJwt(token)) throw new Error("Not a JWT.");
  const [headerRaw, payloadRaw, signatureRaw] = token.split(".");
  const header = JSON.parse(base64url(headerRaw).toString("utf8")) as { alg?: string; kid?: string };
  if (header.alg !== "RS256") throw new Error("Unsupported token algorithm.");
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("Unknown signing key.");
  const valid = verify("RSA-SHA256", Buffer.from(`${headerRaw}.${payloadRaw}`), createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }), base64url(signatureRaw));
  if (!valid) throw new Error("Invalid token signature.");

  const claims = JSON.parse(base64url(payloadRaw).toString("utf8")) as OidcClaims;
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  const audience = options.audience ?? MONITOR_AUDIENCE;
  if (claims.iss !== GITHUB_OIDC_ISSUER) throw new Error("Unexpected issuer.");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) throw new Error("Unexpected audience.");
  if (typeof claims.exp !== "number" || claims.exp + 60 < now) throw new Error("Token expired.");
  if (typeof claims.nbf === "number" && claims.nbf - 60 > now) throw new Error("Token not yet valid.");
  if (!options.repositories.includes(String(claims.repository || "").toLowerCase())) throw new Error("Repository not allowed.");
  if (claims.ref !== "refs/heads/main") throw new Error("Only the main branch may trigger monitoring.");
  return claims;
}

let jwksCache: { keys: Jwk[]; at: number } | null = null;

async function githubKeys(force = false) {
  if (!force && jwksCache && Date.now() - jwksCache.at < 3600_000) return jwksCache.keys;
  const response = await fetch(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`, { cache: "no-store", signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`Could not load GitHub signing keys (${response.status}).`);
  const body = await response.json() as { keys?: Jwk[] };
  jwksCache = { keys: Array.isArray(body.keys) ? body.keys : [], at: Date.now() };
  return jwksCache.keys;
}

/** Verifies a GitHub Actions OIDC token for the monitoring workflow. */
export async function verifyGithubActionsToken(token: string) {
  const repositories = allowedRepositories();
  try {
    return verifyOidcToken(token, await githubKeys(), { repositories });
  } catch (error) {
    // GitHub rotates keys; retry once with a fresh key set.
    if (error instanceof Error && error.message === "Unknown signing key.") return verifyOidcToken(token, await githubKeys(true), { repositories });
    throw error;
  }
}
