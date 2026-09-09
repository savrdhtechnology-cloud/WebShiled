import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { demoAlerts, demoMetrics, demoThreats, demoVisitors, demoWebsites } from "@/lib/demo";

const resources = new Set(["dashboard","websites","visitors","threats","firewall","analytics","reports","alerts","api-keys","webhooks","billing","admin","support"]);

function json(data: unknown, init = 200) {
  return NextResponse.json({ ok: init < 400, data: init < 400 ? data : null, error: init >= 400 ? data : null, meta: { demo: process.env.WEB_SHIELD_DEMO_MODE !== "false", timestamp: new Date().toISOString() } }, { status: init });
}

export async function GET(_: NextRequest, context: { params: Promise<{ resource: string[] }> }) {
  const user = await getCurrentUser();
  if (!user) return json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
  const { resource } = await context.params;
  const key = resource[0] || "";
  if (!resources.has(key)) return json({ code: "NOT_FOUND", message: "Unknown API resource." }, 404);
  if (key === "admin" && !["OWNER","ADMIN"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Admin role required." }, 403);
  if (process.env.WEB_SHIELD_DEMO_MODE === "false") return json({ code: "PROVIDER_NOT_CONNECTED", message: "Production data provider is not configured for this endpoint." }, 501);

  const payload: Record<string,unknown> = {
    dashboard: { metrics: demoMetrics, alerts: demoAlerts, threats: demoThreats.slice(0,3) },
    websites: demoWebsites,
    visitors: demoVisitors,
    threats: demoThreats,
    firewall: { rules: [], enforcementConnected: false, provider: "demo" },
    analytics: { visitors: demoVisitors.length, threats: demoThreats.length, source: "demo" },
    reports: { formats: ["view","csv"], pdf: "integration_ready" },
    alerts: demoAlerts,
    "api-keys": { keys: [], secretExposure: false },
    webhooks: { endpoints: [], signing: "integration_ready" },
    billing: { plan: "FREE", paymentProvider: "not_configured" },
    admin: { clients: 142, activeWebsites: 318, source: "demo" },
    support: { tickets: [] }
  };
  return json(payload[key]);
}

export async function POST(request: NextRequest, context: { params: Promise<{ resource: string[] }> }) {
  const user = await getCurrentUser();
  if (!user) return json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
  const { resource } = await context.params;
  const key = resource[0] || "";
  if (!resources.has(key)) return json({ code: "NOT_FOUND", message: "Unknown API resource." }, 404);
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return json({ code: "INVALID_CONTENT_TYPE", message: "application/json required." }, 415);
  const body = await request.json().catch(() => null) as Record<string,unknown> | null;
  if (!body || Array.isArray(body)) return json({ code: "INVALID_BODY", message: "A JSON object is required." }, 400);
  return json({ code: "INTEGRATION_READY", message: `Write operations for ${key} require a configured production provider/database. No fake mutation was performed.` }, 501);
}
