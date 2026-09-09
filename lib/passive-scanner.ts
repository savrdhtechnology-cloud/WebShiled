import { lookup } from "node:dns/promises";
import net from "node:net";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanFinding = {
  severity: FindingSeverity;
  category: string;
  title: string;
  detail: string;
  impact: string;
  fix: string;
};

const SECURITY_HEADERS = [
  ["strict-transport-security", "HSTS", "Enable Strict-Transport-Security after HTTPS is fully enabled."],
  ["content-security-policy", "Content Security Policy", "Add a restrictive Content-Security-Policy and tune it for your application."],
  ["x-content-type-options", "X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."],
  ["x-frame-options", "X-Frame-Options", "Set X-Frame-Options: DENY/SAMEORIGIN or use CSP frame-ancestors."],
  ["referrer-policy", "Referrer-Policy", "Set Referrer-Policy, for example strict-origin-when-cross-origin."],
  ["permissions-policy", "Permissions-Policy", "Restrict browser capabilities your site does not need."],
  ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "Consider Cross-Origin-Opener-Policy where compatible."],
  ["cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "Define Cross-Origin-Resource-Policy where compatible."]
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
    return p[0] >= 224;
  }
  if (family === 6) {
    const v = ip.toLowerCase();
    return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb");
  }
  return true;
}

async function publicAddresses(hostname: string) {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) throw new Error("Local/private hosts are not allowed.");
  if (net.isIP(host) && isPrivateIp(host)) throw new Error("Private IP addresses are not allowed.");
  const addresses = await lookup(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) throw new Error("Target must resolve only to public internet addresses.");
  return addresses;
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

async function fetchSafely(start: URL, method: "GET" | "HEAD" = "GET") {
  let current = start;
  const chain: string[] = [];
  const started = Date.now();
  for (let hop = 0; hop < 5; hop++) {
    await publicAddresses(current.hostname);
    chain.push(current.toString());
    const response = await fetch(current, {
      method,
      redirect: "manual",
      headers: {
        "user-agent": "WebShield-Passive-Posture-Scanner/2.0",
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

async function probePath(base: URL, path: string) {
  try {
    const url = new URL(path, `${base.protocol}//${base.host}`);
    const result = await fetchSafely(url, "GET");
    return { exists: result.response.status >= 200 && result.response.status < 400, status: result.response.status, finalUrl: result.finalUrl.toString() };
  } catch {
    return { exists: false, status: 0, finalUrl: null };
  }
}

function getSetCookies(headers: Headers) {
  const h = headers as Headers & { getSetCookie?: () => string[] };
  const list = h.getSetCookie?.();
  if (Array.isArray(list) && list.length) return list;
  const single = headers.get("set-cookie");
  return single ? [single] : [];
}

function add(findings: ScanFinding[], severity: FindingSeverity, category: string, title: string, detail: string, impact: string, fix: string) {
  findings.push({ severity, category, title, detail, impact, fix });
}

function severityWeight(severity: FindingSeverity) {
  return severity === "CRITICAL" ? 30 : severity === "HIGH" ? 20 : severity === "MEDIUM" ? 10 : severity === "LOW" ? 4 : 0;
}

export async function runPassiveScan(value: unknown) {
  const target = normalizeInput(value);
  const { response, finalUrl, chain, responseMs } = await fetchSafely(target);
  const addresses = await publicAddresses(finalUrl.hostname);
  const https = finalUrl.protocol === "https:";
  const statusHealthy = response.status >= 200 && response.status < 400;

  const httpProbe = await (async () => {
    try {
      const httpUrl = new URL(finalUrl.toString());
      httpUrl.protocol = "http:";
      const r = await fetchSafely(httpUrl, "HEAD");
      return { redirectsToHttps: r.finalUrl.protocol === "https:", status: r.response.status, finalUrl: r.finalUrl.toString() };
    } catch {
      return { redirectsToHttps: false, status: 0, finalUrl: null };
    }
  })();

  const checks = SECURITY_HEADERS.map(([key, label, fix]) => ({
    key,
    label,
    present: Boolean(response.headers.get(key)),
    value: response.headers.get(key) || null,
    fix
  }));

  const server = response.headers.get("server");
  const poweredBy = response.headers.get("x-powered-by");
  const cors = response.headers.get("access-control-allow-origin");
  const csp = response.headers.get("content-security-policy") || "";
  const hsts = response.headers.get("strict-transport-security") || "";
  const cookies = getSetCookies(response.headers);
  const insecureCookies = cookies.filter(c => !/;\s*secure(?:;|$)/i.test(c));
  const noHttpOnlyCookies = cookies.filter(c => !/;\s*httponly(?:;|$)/i.test(c));
  const noSameSiteCookies = cookies.filter(c => !/;\s*samesite=/i.test(c));
  const securityTxt = await probePath(finalUrl, "/.well-known/security.txt");
  const robotsTxt = await probePath(finalUrl, "/robots.txt");

  const findings: ScanFinding[] = [];
  if (!https) add(findings, "HIGH", "Transport", "HTTPS is not active", "The final page is served over HTTP.", "Traffic can be read or altered in transit.", "Enable HTTPS and redirect every HTTP request to HTTPS.");
  if (https && !httpProbe.redirectsToHttps) add(findings, "MEDIUM", "Transport", "HTTP does not consistently redirect to HTTPS", "The HTTP probe did not end on HTTPS.", "Visitors may reach an unencrypted version of the site.", "Configure a permanent HTTP→HTTPS redirect at the CDN, load balancer, or web server.");

  for (const check of checks.filter(c => !c.present)) {
    const severity: FindingSeverity = check.key === "content-security-policy" ? "HIGH" : check.key === "strict-transport-security" ? "MEDIUM" : check.key === "x-frame-options" || check.key === "x-content-type-options" ? "MEDIUM" : "LOW";
    add(findings, severity, "Security Headers", `${check.label} missing`, `${check.label} was not detected on the final response.`, "A useful browser-side security control is absent or cannot be confirmed.", check.fix);
  }

  if (csp) {
    if (/unsafe-eval/i.test(csp)) add(findings, "MEDIUM", "Content Security Policy", "CSP allows unsafe-eval", "The policy contains unsafe-eval.", "Injected script paths may have more execution options.", "Remove unsafe-eval where possible and use nonces/hashes for required scripts.");
    if (/unsafe-inline/i.test(csp)) add(findings, "LOW", "Content Security Policy", "CSP allows unsafe-inline", "The policy contains unsafe-inline.", "Inline script/style allowance weakens CSP protections.", "Prefer nonces or hashes and remove unsafe-inline where feasible.");
    if (/default-src\s+\*/i.test(csp) || /script-src[^;]*\*/i.test(csp)) add(findings, "MEDIUM", "Content Security Policy", "CSP contains broad wildcard sources", "A broad wildcard source was detected.", "The policy may trust more origins than necessary.", "Replace broad wildcards with explicit trusted origins.");
  }

  if (hsts && !/max-age=(\d+)/i.test(hsts)) add(findings, "LOW", "Transport", "HSTS max-age could not be confirmed", "HSTS exists but a max-age value was not recognized.", "Browsers may not retain strict HTTPS enforcement as intended.", "Set a valid Strict-Transport-Security max-age value after confirming HTTPS readiness.");
  if (cors === "*") add(findings, "MEDIUM", "Cross-Origin", "CORS allows every origin", "Access-Control-Allow-Origin is set to *.", "Cross-origin access may be broader than intended for sensitive responses.", "Restrict CORS to known origins for endpoints that return private or user-specific data.");

  if (poweredBy) add(findings, "LOW", "Information Exposure", "Technology header exposed", `X-Powered-By reports ${poweredBy}.`, "Technology disclosure can improve attacker reconnaissance.", "Remove unnecessary X-Powered-By headers where possible.");
  if (server) add(findings, "INFO", "Information Exposure", "Server header visible", `Server reports ${server}.`, "This is mainly reconnaissance information unless a precise vulnerable version is exposed.", "Reduce unnecessary server/version disclosure when your platform permits it.");

  if (cookies.length) {
    if (insecureCookies.length) add(findings, "MEDIUM", "Cookies", "Some cookies lack Secure", `${insecureCookies.length} observed Set-Cookie value(s) did not include Secure.`, "Such cookies may be sent over non-HTTPS connections in some configurations.", "Mark session and sensitive cookies Secure once HTTPS is enforced.");
    if (noHttpOnlyCookies.length) add(findings, "LOW", "Cookies", "Some cookies lack HttpOnly", `${noHttpOnlyCookies.length} observed cookie(s) did not include HttpOnly.`, "Client-side script may be able to access those cookies.", "Use HttpOnly for session/authentication cookies that do not require JavaScript access.");
    if (noSameSiteCookies.length) add(findings, "LOW", "Cookies", "Some cookies lack SameSite", `${noSameSiteCookies.length} observed cookie(s) did not include SameSite.`, "Cross-site request behavior may be broader than intended.", "Set SameSite=Lax or Strict where compatible; use None only with Secure when cross-site behavior is required.");
  }

  if (!securityTxt.exists) add(findings, "INFO", "Disclosure Process", "security.txt not found", "No /.well-known/security.txt was found.", "Security researchers have no standardized reporting contact from this endpoint.", "Publish a security.txt file if you want a formal vulnerability-reporting contact.");

  const headersPresent = checks.filter(c => c.present).length;
  const penalty = findings.reduce((sum, f) => sum + severityWeight(f.severity), 0);
  const baseline = (https ? 20 : 0) + (statusHealthy ? 10 : 0) + (headersPresent / checks.length) * 45 + (httpProbe.redirectsToHttps ? 5 : 0) + (securityTxt.exists ? 5 : 0) + 15;
  const score = Math.max(0, Math.min(100, Math.round(baseline - Math.min(35, penalty * 0.45))));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {} as Record<FindingSeverity, number>);
  const overallRisk = counts.CRITICAL ? "CRITICAL" : counts.HIGH ? "HIGH" : counts.MEDIUM ? "MEDIUM" : counts.LOW ? "LOW" : "INFO";

  const technologies = [
    ...(server ? [{ signal: "Server", value: server }] : []),
    ...(poweredBy ? [{ signal: "X-Powered-By", value: poweredBy }] : []),
    ...(response.headers.get("x-vercel-id") ? [{ signal: "Hosting signal", value: "Vercel" }] : []),
    ...(response.headers.get("cf-ray") ? [{ signal: "Edge/CDN signal", value: "Cloudflare" }] : [])
  ];

  return {
    requestedUrl: target.toString(),
    finalUrl: finalUrl.toString(),
    hostname: finalUrl.hostname,
    status: response.status,
    statusText: response.statusText,
    responseMs,
    https,
    redirectedToHttps: httpProbe.redirectsToHttps,
    httpProbe,
    redirectChain: chain,
    securityScore: score,
    grade,
    overallRisk,
    findingCounts: { CRITICAL: counts.CRITICAL || 0, HIGH: counts.HIGH || 0, MEDIUM: counts.MEDIUM || 0, LOW: counts.LOW || 0, INFO: counts.INFO || 0 },
    findings,
    headers: checks,
    server: server || null,
    poweredBy: poweredBy || null,
    cors: cors || null,
    cookies: { observed: cookies.length, missingSecure: insecureCookies.length, missingHttpOnly: noHttpOnlyCookies.length, missingSameSite: noSameSiteCookies.length },
    dns: { resolved: true, addresses: addresses.map(a => ({ address: a.address, family: a.family })) },
    technologies,
    resources: { securityTxt, robotsTxt },
    scannedAt: new Date().toISOString(),
    mode: "LIVE_PASSIVE_POSTURE_SCAN",
    capabilities: {
      visitorMonitoring: "REQUIRES_INTEGRATION",
      threatDetection: "REQUIRES_INTEGRATION",
      websiteProtection: "REQUIRES_INTEGRATION",
      botDetection: "REQUIRES_INTEGRATION",
      analytics: "SCAN_DATA_AVAILABLE",
      alerts: "REQUIRES_INTEGRATION",
      easyIntegration: "AVAILABLE",
      reports: "SCAN_REPORT_AVAILABLE"
    },
    note: "Passive external posture scan only. Real-time visitors, threat detection and automatic blocking require WebShield to be integrated into the website traffic path."
  };
}
