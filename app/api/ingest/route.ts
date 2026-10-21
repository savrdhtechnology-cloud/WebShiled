import { createHash, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { adminConfigured, createAdminClient } from "@/lib/supabase/admin";
import { applyPolicyRules, evaluateRequest, isLoginAttempt, type IpRule, type PolicyRule } from "@/lib/security-engine/request-analysis";
import { raiseAlert } from "@/lib/monitoring/alerts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Server-side integration endpoint. A website's middleware calls this for each
// request and enforces the returned decision (ALLOW / RATE_LIMIT / BLOCK).
//   POST /webshield/api/ingest
//   x-webshield-site: <collector site key>
//   authorization: Bearer <server key from Websites → Integration>
//   { ip, method, path, query, userAgent, referrer, country }

type Site = { id: string; organization_id: string; domain: string; ingest_secret_hash: string | null; collector_enabled: boolean };

const siteCache = new Map<string, { site: Site | null; rules: IpRule[]; policies: PolicyRule[]; at: number }>();
const counters = new Map<string, number[]>();
const lastTouch = new Map<string, number>();
const SITE_TTL = 30_000;

function hash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function sameHash(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function hit(key: string, windowMs: number, now: number) {
  const list = (counters.get(key) || []).filter(t => now - t < windowMs);
  list.push(now);
  counters.set(key, list);
  if (counters.size > 20_000) {
    for (const [k, v] of counters) { if (!v.length || now - v[v.length - 1] > 300_000) counters.delete(k); }
  }
  return list.length;
}

async function loadSite(siteKey: string) {
  const cached = siteCache.get(siteKey);
  if (cached && Date.now() - cached.at < SITE_TTL) return cached;
  const admin = createAdminClient();
  const { data: site } = await admin.from("websites")
    .select("id,organization_id,domain,ingest_secret_hash,collector_enabled")
    .eq("collector_key", siteKey).maybeSingle();
  let rules: IpRule[] = [];
  let policies: PolicyRule[] = [];
  if (site) {
    const [ip, fw] = await Promise.all([
      admin.from("ip_rules").select("id,ip_cidr,action,website_id,expires_at").eq("organization_id", site.organization_id),
      admin.from("firewall_rules").select("id,name,priority,enabled,action,website_id,conditions").eq("organization_id", site.organization_id).eq("enabled", true)
    ]);
    rules = (ip.data || []).map(r => ({ ...r, ip_cidr: String(r.ip_cidr) })) as IpRule[];
    policies = (fw.data || []) as PolicyRule[];
  }
  const entry = { site: (site as Site) || null, rules, policies, at: Date.now() };
  siteCache.set(siteKey, entry);
  return entry;
}

function sessionStatus(action: string, score: number) {
  if (action === "BLOCK") return "BLOCKED";
  if (score >= 50) return "THREAT";
  if (score >= 25) return "SUSPICIOUS";
  return "SAFE";
}

export async function POST(request: NextRequest) {
  if (!adminConfigured()) return NextResponse.json({ ok: false, action: "ALLOW", error: "ingest_not_configured" }, { status: 503 });
  const siteKey = request.headers.get("x-webshield-site") || "";
  const secret = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!siteKey || !secret) return NextResponse.json({ ok: false, action: "ALLOW", error: "missing_credentials" }, { status: 401 });

  const { site, rules, policies } = await loadSite(siteKey.slice(0, 128));
  if (!site || !site.ingest_secret_hash || !sameHash(hash(secret), site.ingest_secret_hash)) {
    return NextResponse.json({ ok: false, action: "ALLOW", error: "invalid_credentials" }, { status: 401 });
  }

  const body = await request.json().catch(() => null) as null | { ip?: string; method?: string; path?: string; query?: string; userAgent?: string; referrer?: string; country?: string };
  if (!body?.path) return NextResponse.json({ ok: false, action: "ALLOW", error: "invalid_payload" }, { status: 400 });

  const facts = {
    ip: String(body.ip || "").slice(0, 64),
    method: String(body.method || "GET").toUpperCase().slice(0, 10),
    path: String(body.path).slice(0, 2000),
    query: String(body.query || "").slice(0, 2000),
    userAgent: String(body.userAgent || "").slice(0, 400)
  };
  const now = Date.now();
  const ipKey = `${site.id}|${facts.ip || "unknown"}`;
  const perMinute = hit(`r|${ipKey}`, 60_000, now);
  const logins = isLoginAttempt(facts) ? hit(`l|${ipKey}`, 300_000, now) : (counters.get(`l|${ipKey}`) || []).filter(t => now - t < 300_000).length;
  const scored = evaluateRequest(facts, { rules, websiteId: site.id, requestsLastMinute: perMinute, loginPostsLastFiveMinutes: logins });
  const result = applyPolicyRules(scored, { ...facts, country: String(body.country || "") }, policies, site.id);

  const admin = createAdminClient();
  const url = `${facts.path}${facts.query}`.slice(0, 2000);
  const ip = /^[0-9a-f.:]+$/i.test(facts.ip) ? facts.ip : null;
  const writes: PromiseLike<unknown>[] = [
    admin.from("visitor_sessions").insert({
      organization_id: site.organization_id,
      website_id: site.id,
      requested_url: url,
      request_method: facts.method,
      risk_score: result.riskScore,
      status: sessionStatus(result.action, result.riskScore),
      client_ip: ip,
      user_agent: facts.userAgent || null,
      source: "server"
    })
  ];

  const top = [...result.signals].sort((a, b) => b.score - a.score)[0];
  if (top && (result.riskScore >= 50 || result.action !== "ALLOW")) {
    const severity = result.signals.some(s => s.severity === "CRITICAL") ? "CRITICAL" : result.riskScore >= 70 ? "HIGH" : "MEDIUM";
    writes.push(admin.from("threat_events").insert({
      organization_id: site.organization_id,
      website_id: site.id,
      type: top.code,
      severity,
      source_ip: ip,
      target_url: url,
      risk_score: result.riskScore,
      status: "OPEN",
      action_taken: result.action,
      metadata: { signals: result.signals, method: facts.method, userAgent: facts.userAgent, country: body.country || null, rule: result.matchedRule?.id || null, policyRule: result.policyRule?.id || null }
    }));
    if (severity !== "MEDIUM" && !result.matchedRule) {
      writes.push(raiseAlert(admin, {
        organizationId: site.organization_id,
        websiteId: site.id,
        type: `TRAFFIC_${top.code}`,
        severity,
        title: `${site.domain}: ${top.explanation.replace(/\.$/, "")}`,
        message: `${facts.method} ${url.slice(0, 200)} from ${facts.ip || "unknown IP"}${body.country ? ` (${body.country})` : ""}. Decision: ${result.action}. Signals: ${result.signals.map(s => s.code).join(", ")}.`,
        source: "traffic",
        dedupeKey: `traffic:${site.id}:${top.code}:${facts.ip || "unknown"}`,
        metadata: { ip: facts.ip, riskScore: result.riskScore, action: result.action }
      }).catch(() => null));
    }
  }
  if ((lastTouch.get(site.id) || 0) < now - 60_000) {
    lastTouch.set(site.id, now);
    writes.push(admin.from("websites").update({ last_ingest_at: new Date(now).toISOString(), last_event_at: new Date(now).toISOString(), integration_status: "SERVER_CONNECTED" }).eq("id", site.id));
  }
  await Promise.allSettled(writes);

  return NextResponse.json({ ok: true, action: result.action, riskScore: result.riskScore, signals: result.signals.map(s => s.code) }, { headers: { "cache-control": "no-store" } });
}
