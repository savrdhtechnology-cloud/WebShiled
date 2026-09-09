import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns/promises";
import net from "node:net";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SECURITY_HEADERS = [
  ["strict-transport-security", "HSTS", "Enable Strict-Transport-Security after HTTPS is fully enabled."],
  ["content-security-policy", "Content Security Policy", "Add a restrictive Content-Security-Policy and tune it for your application."],
  ["x-content-type-options", "X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."],
  ["x-frame-options", "X-Frame-Options", "Set X-Frame-Options or use CSP frame-ancestors to control framing."],
  ["referrer-policy", "Referrer-Policy", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."],
  ["permissions-policy", "Permissions-Policy", "Restrict browser capabilities you do not use with Permissions-Policy."],
  ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "Consider Cross-Origin-Opener-Policy where compatible."],
  ["cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "Define Cross-Origin-Resource-Policy where compatible."]
] as const;

const buckets = new Map<string, { count: number; resetAt: number }>();
function rateLimit(key: string) {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || existing.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + 10 * 60_000 });
    return false;
  }
  existing.count += 1;
  return existing.count > 10;
}

function isPrivateIp(ip: string) {
  const family = net.isIP(ip);
  if (family === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    return p[0] >= 224;
  }
  if (family === 6) {
    const v = ip.toLowerCase();
    return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb");
  }
  return true;
}

async function validatePublicHost(hostname: string) {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) throw new Error("Local/private hosts are not allowed.");
  if (net.isIP(host) && isPrivateIp(host)) throw new Error("Private IP addresses are not allowed.");
  const addresses = await lookup(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) throw new Error("Target must resolve only to public internet addresses.");
}

function normalizeInput(value: unknown) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > 253) throw new Error("Enter a valid website domain.");
  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(withProtocol);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Only HTTP/HTTPS websites can be scanned.");
  if (url.username || url.password) throw new Error("Credential URLs are not allowed.");
  url.hash = "";
  return url;
}

async function fetchSafely(start: URL) {
  let current = start;
  const chain: string[] = [];
  const started = Date.now();
  for (let hop = 0; hop < 4; hop++) {
    await validatePublicHost(current.hostname);
    chain.push(current.toString());
    const response = await fetch(current, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": "WebShield-Public-Posture-Scanner/1.0", accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1" },
      signal: AbortSignal.timeout(8000),
      cache: "no-store"
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) return { response, finalUrl: current, chain, responseMs: Date.now() - started };
      current = new URL(location, current);
      if (!['http:', 'https:'].includes(current.protocol)) throw new Error("Redirected to an unsupported protocol.");
      continue;
    }
    return { response, finalUrl: current, chain, responseMs: Date.now() - started };
  }
  throw new Error("Too many redirects.");
}

export async function POST(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (rateLimit(ip)) return NextResponse.json({ ok: false, error: "Scan limit reached. Try again later." }, { status: 429 });

  try {
    const body = await request.json();
    const target = normalizeInput(body?.url);
    const { response, finalUrl, chain, responseMs } = await fetchSafely(target);
    const checks = SECURITY_HEADERS.map(([key, label, fix]) => ({ key, label, present: Boolean(response.headers.get(key)), value: response.headers.get(key) || null, fix }));
    const present = checks.filter(c => c.present).length;
    const https = finalUrl.protocol === "https:";
    const statusHealthy = response.status >= 200 && response.status < 400;
    const server = response.headers.get("server");
    const poweredBy = response.headers.get("x-powered-by");
    const score = Math.max(0, Math.min(100, Math.round((https ? 25 : 0) + (statusHealthy ? 15 : 0) + (present / SECURITY_HEADERS.length) * 55 + (target.protocol === "http:" && https ? 5 : 0))));
    const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
    const findings = [
      ...(!https ? [{ severity: "HIGH", title: "HTTPS not active", detail: "The final page is not using HTTPS.", fix: "Enable HTTPS and redirect all HTTP traffic to HTTPS." }] : []),
      ...checks.filter(c => !c.present).map(c => ({ severity: c.key === "content-security-policy" || c.key === "strict-transport-security" ? "MEDIUM" : "LOW", title: `${c.label} missing`, detail: `${c.label} was not detected on the final response.`, fix: c.fix })),
      ...(poweredBy ? [{ severity: "LOW", title: "Technology header exposed", detail: `X-Powered-By exposes ${poweredBy}.`, fix: "Remove unnecessary technology-identifying response headers where possible." }] : []),
      ...(server ? [{ severity: "INFO", title: "Server header visible", detail: `Server header reports ${server}.`, fix: "Reduce unnecessary server-version disclosure where your hosting stack permits it." }] : [])
    ];

    return NextResponse.json({ ok: true, scan: {
      hostname: finalUrl.hostname, requestedUrl: target.toString(), finalUrl: finalUrl.toString(), status: response.status, responseMs, https,
      redirectHops: Math.max(0, chain.length - 1), securityScore: score, grade, headers: checks, server: server || null, poweredBy: poweredBy || null,
      findings, scannedAt: new Date().toISOString(), mode: "LIVE_PASSIVE_POSTURE_SCAN",
      capabilities: {
        visitorMonitoring: "REQUIRES_INTEGRATION", threatDetection: "REQUIRES_INTEGRATION", websiteProtection: "REQUIRES_INTEGRATION",
        botDetection: "REQUIRES_INTEGRATION", analytics: "PARTIAL_SCAN_DATA", alerts: "REQUIRES_INTEGRATION", easyIntegration: "AVAILABLE", reports: "SCAN_REPORT_AVAILABLE"
      },
      note: "External posture scan only. Real-time traffic monitoring and automatic blocking require WebShield to be connected to the website traffic path."
    }}, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ ok: false, error: error instanceof Error ? error.message : "Scan failed." }, { status: 400 });
  }
}
