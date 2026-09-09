import { NextRequest, NextResponse } from "next/server";
import { SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL } from "@/lib/supabase/config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED_ORIGINS = new Set([
  "https://savrdhfinancialservices.com",
  "https://www.savrdhfinancialservices.com"
]);

const buckets = new Map<string, { count: number; resetAt: number }>();
function limited(ip: string) {
  const now = Date.now();
  const current = buckets.get(ip);
  if (!current || current.resetAt < now) {
    buckets.set(ip, { count: 1, resetAt: now + 60_000 });
    return false;
  }
  current.count += 1;
  return current.count > 120;
}

function cors(origin: string | null) {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : "";
  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    "cache-control": "no-store",
    vary: "Origin"
  };
}

function browserInfo(ua: string) {
  const browser = /Edg\//i.test(ua) ? "Edge" : /OPR\//i.test(ua) ? "Opera" : /Chrome\//i.test(ua) ? "Chrome" : /Safari\//i.test(ua) && !/Chrome\//i.test(ua) ? "Safari" : /Firefox\//i.test(ua) ? "Firefox" : "Other";
  const os = /Windows NT/i.test(ua) ? "Windows" : /Android/i.test(ua) ? "Android" : /iPhone|iPad|iPod/i.test(ua) ? "iOS/iPadOS" : /Mac OS X/i.test(ua) ? "macOS" : /Linux/i.test(ua) ? "Linux" : "Other";
  const device = /Mobile|Android|iPhone|iPod/i.test(ua) ? "Mobile" : /iPad|Tablet/i.test(ua) ? "Tablet" : "Desktop";
  return { browser, os, device };
}

export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, { status: 204, headers: cors(request.headers.get("origin")) });
}

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return NextResponse.json({ ok: false, error: "origin_not_allowed" }, { status: 403, headers: cors(origin) });
  }

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || request.headers.get("x-real-ip") || "";
  if (limited(ip || "unknown")) {
    return NextResponse.json({ ok: false, error: "rate_limited" }, { status: 429, headers: cors(origin) });
  }

  const body = await request.json().catch(() => null) as null | {
    siteKey?: string;
    url?: string;
    referrer?: string;
    visitorKey?: string;
    webdriver?: boolean;
  };
  if (!body?.siteKey || !body?.url || !body?.visitorKey) {
    return NextResponse.json({ ok: false, error: "invalid_payload" }, { status: 400, headers: cors(origin) });
  }

  const ua = request.headers.get("user-agent") || "";
  const { browser, os, device } = browserInfo(ua);
  const botByUa = /bot|crawler|spider|headless|phantom|selenium|playwright|puppeteer/i.test(ua);
  const isBot = Boolean(body.webdriver) || botByUa;
  const country = request.headers.get("x-vercel-ip-country") || "";
  const city = decodeURIComponent(request.headers.get("x-vercel-ip-city") || "");

  const rpc = await fetch(`${SUPABASE_URL}/rest/v1/rpc/webshield_ingest_event`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_PUBLISHABLE_KEY,
      authorization: `Bearer ${SUPABASE_PUBLISHABLE_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      p_collector_key: String(body.siteKey).slice(0, 128),
      p_origin: origin,
      p_ip: ip,
      p_country: country,
      p_city: city,
      p_device: device,
      p_browser: browser,
      p_os: os,
      p_referrer: String(body.referrer || "").slice(0, 1000),
      p_url: String(body.url).slice(0, 2000),
      p_visitor_key: String(body.visitorKey).slice(0, 128),
      p_is_bot: isBot
    }),
    cache: "no-store"
  });

  const result = await rpc.json().catch(() => null);
  if (!rpc.ok || !result?.ok) {
    return NextResponse.json({ ok: false, error: result?.error || "collector_failed" }, { status: 400, headers: cors(origin) });
  }

  return NextResponse.json({ ok: true }, { headers: cors(origin) });
}
