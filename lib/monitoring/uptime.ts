import "server-only";

import tls from "node:tls";
import { fetchSafely, publicAddresses } from "@/lib/passive-scanner";

export type UptimeStatus = "UP" | "DEGRADED" | "DOWN";

export type UptimeResult = {
  status: UptimeStatus;
  ok: boolean;
  statusCode: number | null;
  responseMs: number | null;
  error: string | null;
  finalUrl: string | null;
  ssl: {
    checked: boolean;
    valid: boolean;
    expiresAt: string | null;
    daysLeft: number | null;
    issuer: string | null;
    error: string | null;
  };
  checkedAt: string;
};

export function classifyHttpStatus(code: number | null): UptimeStatus {
  if (!code) return "DOWN";
  if (code >= 500) return "DOWN";
  if (code >= 400 && code !== 401 && code !== 403) return "DEGRADED";
  return "UP";
}

/** Connects with TLS to the resolved public address and reads the certificate. */
export async function checkCertificate(hostname: string, timeoutMs = 8000): Promise<UptimeResult["ssl"]> {
  try {
    const [address] = await publicAddresses(hostname);
    return await new Promise(resolve => {
      const socket = tls.connect({
        host: address.address,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: timeoutMs
      }, () => {
        const cert = socket.getPeerCertificate();
        const expires = cert?.valid_to ? new Date(cert.valid_to) : null;
        const authorized = socket.authorized;
        const authError = socket.authorizationError ? String(socket.authorizationError) : null;
        socket.end();
        const daysLeft = expires && Number.isFinite(expires.getTime()) ? Math.floor((expires.getTime() - Date.now()) / 86400000) : null;
        const issuer = cert?.issuer ? String((cert.issuer as unknown as Record<string, string>).O || (cert.issuer as unknown as Record<string, string>).CN || "") || null : null;
        resolve({ checked: true, valid: authorized, expiresAt: expires && Number.isFinite(expires.getTime()) ? expires.toISOString() : null, daysLeft, issuer, error: authorized ? null : authError || "Certificate is not trusted." });
      });
      socket.on("timeout", () => { socket.destroy(); resolve({ checked: false, valid: false, expiresAt: null, daysLeft: null, issuer: null, error: "TLS handshake timed out." }); });
      socket.on("error", error => resolve({ checked: false, valid: false, expiresAt: null, daysLeft: null, issuer: null, error: error.message }));
    });
  } catch (error) {
    return { checked: false, valid: false, expiresAt: null, daysLeft: null, issuer: null, error: error instanceof Error ? error.message : "TLS check failed." };
  }
}

export async function checkUptime(domain: string): Promise<UptimeResult> {
  const checkedAt = new Date().toISOString();
  const host = domain.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
  const [http, ssl] = await Promise.all([
    (async () => {
      const started = Date.now();
      try {
        const { response, finalUrl } = await fetchSafely(new URL(`https://${host}/`), "GET");
        // Drain a little of the body so the connection is released.
        await response.body?.cancel().catch(() => {});
        return { statusCode: response.status, responseMs: Date.now() - started, finalUrl: finalUrl.toString(), error: null as string | null };
      } catch (error) {
        return { statusCode: null, responseMs: null, finalUrl: null, error: error instanceof Error ? error.message : "Request failed." };
      }
    })(),
    checkCertificate(host)
  ]);
  const status = classifyHttpStatus(http.statusCode);
  return { status, ok: status !== "DOWN", ...http, ssl, checkedAt };
}
