import { connect, type PeerCertificate } from "node:tls";
import { lookup } from "node:dns/promises";
import net from "node:net";

export type CertificateInspection = {
  status: "CHECKED" | "UNAVAILABLE";
  hostname: string;
  valid: boolean | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  authorizationError: string | null;
  tlsVersion: string | null;
  reason?: string;
};

function allowedAddress(ip: string) {
  if (net.isIP(ip) === 4) {
    const [a,b] = ip.split(".").map(Number);
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51) || (a === 203 && b === 0)
    );
  }
  if (net.isIP(ip) === 6) {
    const x = ip.toLowerCase();
    // Conservative: only globally-routed 2000::/3 IPv6; mapped IPv4 is rejected.
    return /^[23][0-9a-f]{0,3}:/.test(x);
  }
  return false;
}

/**
 * Read-only TLS handshake with DNS pinning and hostname/SNI verification.
 * Never requests a webpage and never extracts certificate private keys.
 */
export async function inspectCertificate(hostname: string): Promise<CertificateInspection> {
  const unavailable = (reason: string): CertificateInspection => ({
    status: "UNAVAILABLE", hostname, valid: null, subject: null, issuer: null,
    validFrom: null, validTo: null, daysRemaining: null,
    authorizationError: null, tlsVersion: null, reason
  });
  if (!hostname || net.isIP(hostname) || hostname === "localhost" || !/^[a-z\d.-]+$/i.test(hostname))
    return unavailable("Certificate inspection needs a public DNS hostname.");
  try {
    const addresses = await lookup(hostname, { all: true });
    if (!addresses.length || addresses.some(a => !allowedAddress(a.address)))
      return unavailable("Hostname resolves to an unsupported or restricted address.");
    const address = addresses[0];
    return await new Promise<CertificateInspection>(resolve => {
      let finished = false;
      const finish = (value: CertificateInspection) => {
        if (finished) return;
        finished = true;
        socket.destroy();
        resolve(value);
      };
      const socket = connect({
        host: address.address, port: 443, family: address.family,
        servername: hostname, rejectUnauthorized: false,
        timeout: 6500
      });
      socket.once("secureConnect", () => {
        const cert: PeerCertificate = socket.getPeerCertificate();
        const from = cert.valid_from ? Date.parse(cert.valid_from) : NaN;
        const to = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
        const days = Number.isFinite(to) ? Math.ceil((to - Date.now()) / 86400000) : null;
        const nameError = cert.raw ? (awaitCheckHostname(hostname, cert)) : "Certificate not presented.";
        const authorized = !socket.authorizationError && !nameError && Number.isFinite(from) && Number.isFinite(to) && from <= Date.now() && to >= Date.now();
        finish({
          status: "CHECKED", hostname, valid: authorized,
          subject: cert.subject?.CN || null, issuer: cert.issuer?.CN || null,
          validFrom: cert.valid_from || null, validTo: cert.valid_to || null,
          daysRemaining: days, authorizationError: String(socket.authorizationError || nameError || "") || null,
          tlsVersion: socket.getProtocol() || null
        });
      });
      socket.once("timeout", () => finish(unavailable("TLS handshake timed out.")));
      socket.once("error", () => finish(unavailable("TLS handshake failed.")));
    });
  } catch {
    return unavailable("Certificate inspection could not be completed.");
  }
}

function awaitCheckHostname(hostname: string, cert: PeerCertificate): string | null {
  // Node validates SANs / CN matching, including wildcards.
  const error = requireHostnameCheck(hostname, cert);
  return error ? error.message : null;
}

import { checkServerIdentity } from "node:tls";
function requireHostnameCheck(hostname: string, cert: PeerCertificate): Error | undefined {
  return checkServerIdentity(hostname, cert);
}
