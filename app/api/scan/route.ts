import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { getCurrentUser } from "@/lib/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SECURITY_HEADERS = [
  ["strict-transport-security", "HSTS"],
  ["content-security-policy", "Content Security Policy"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["x-frame-options", "X-Frame-Options"],
  ["referrer-policy", "Referrer-Policy"],
  ["permissions-policy", "Permissions-Policy"],
  ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy"],
  ["cross-origin-resource-policy", "Cross-Origin-Resource-Policy"]
] as const;

function isPrivateIp(ip: string) {
  const family = net.isIP(ip);
  if (family === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    if (p[0] >= 224) return true;
    return false;
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
      headers: {
        "user-agent": "WebShield-V1-Passive-Scanner/1.0",
        accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"
      },
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
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ ok: false, error: "Authentication required." }, { status: 401 });

  try {
    const body = await request.json();
    const target = normalizeInput(body?.url);
    const { response, finalUrl, chain, responseMs } = await fetchSafely(target);

    const checks = SECURITY_HEADERS.map(([key, label]) => ({
      key,
      label,
      present: Boolean(response.headers.get(key)),
      value: response.headers.get(key) || null
    }));
    const present = checks.filter(c => c.present).length;
    const https = finalUrl.protocol === "https:";
    const redirectedToHttps = target.protocol === "http:" && https;
    const statusHealthy = response.status >= 200 && response.status < 400;
    const score = Math.max(0, Math.min(100, Math.round(
      (https ? 25 : 0) +
      (statusHealthy ? 15 : 0) +
      (present / SECURITY_HEADERS.length) * 55 +
      (redirectedToHttps ? 5 : 0)
    )));

    const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
    const server = response.headers.get("server");
    const poweredBy = response.headers.get("x-powered-by");

    return NextResponse.json({
      ok: true,
      scan: {
        requestedUrl: target.toString(),
        finalUrl: finalUrl.toString(),
        hostname: finalUrl.hostname,
        status: response.status,
        statusText: response.statusText,
        responseMs,
        https,
        redirectedToHttps,
        redirectChain: chain,
        securityScore: score,
        grade,
        headers: checks,
        server: server || null,
        poweredBy: poweredBy || null,
        scannedAt: new Date().toISOString(),
        mode: "PASSIVE_EXTERNAL_SCAN",
        note: "Passive HTTP/TLS posture only. This is not an exploit, vulnerability, malware, WAF or DDoS penetration test."
      }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";
    return NextResponse.json({ ok: false, error: message }, { status: 400 });
  }
}
