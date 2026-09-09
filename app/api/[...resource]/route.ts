import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";

const resources = new Set(["dashboard","websites","visitors","threats","firewall","analytics","reports","alerts","billing","admin","support"]);

function json(data: unknown, init = 200, meta: Record<string, unknown> = {}) {
  return NextResponse.json({
    ok: init < 400,
    data: init < 400 ? data : null,
    error: init >= 400 ? data : null,
    meta: { source: "supabase", timestamp: new Date().toISOString(), ...meta }
  }, { status: init });
}

async function countRows(client: Awaited<ReturnType<typeof createClient>>, table: string, orgId: string, extra?: (q: any) => any) {
  let query: any = client.from(table).select("*", { count: "exact", head: true }).eq("organization_id", orgId);
  if (extra) query = extra(query);
  const { count, error } = await query;
  if (error) throw error;
  return count || 0;
}

function normalizeDomain(input: string) {
  const raw = input.trim().toLowerCase();
  if (!raw) return "";
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    return new URL(withProtocol).hostname.replace(/^www\./, "");
  } catch {
    return raw.replace(/^https?:\/\//, "").split("/")[0].replace(/^www\./, "").replace(/:\d+$/, "");
  }
}

export async function GET(_: NextRequest, context: { params: Promise<{ resource: string[] }> }) {
  const user = await getCurrentUser();
  if (!user) return json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
  if (user.demo) return json({ code: "REAL_ACCOUNT_REQUIRED", message: "Demo sessions do not receive fake backend telemetry. Register a real WebShield account to use database-backed modules." }, 409, { demo: true });
  if (!user.organizationId || user.organizationId === "unassigned") return json({ code: "NO_WORKSPACE", message: "No WebShield workspace is assigned to this account." }, 409);

  const { resource } = await context.params;
  const key = resource[0] || "";
  if (!resources.has(key)) return json({ code: "NOT_FOUND", message: "Unknown API resource." }, 404);
  if (key === "admin" && !["OWNER","ADMIN"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Admin role required." }, 403);

  const client = await createClient();
  const orgId = user.organizationId;

  try {
    if (key === "dashboard") {
      const activeSince = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const [websites, visitors, activeVisitors, threats, blocked, alertsCount, threatRows, alertRows, websiteRows, visitorRows, sessionRows] = await Promise.all([
        countRows(client, "websites", orgId),
        countRows(client, "visitors", orgId),
        countRows(client, "visitors", orgId, q => q.gte("last_seen_at", activeSince)),
        countRows(client, "threat_events", orgId),
        countRows(client, "visitor_sessions", orgId, q => q.eq("status", "BLOCKED")),
        countRows(client, "alerts", orgId, q => q.is("acknowledged_at", null)),
        client.from("threat_events").select("id,type,severity,source_ip,target_url,risk_score,status,action_taken,occurred_at").eq("organization_id", orgId).order("occurred_at", { ascending: false }).limit(12),
        client.from("alerts").select("id,type,severity,title,message,acknowledged_at,created_at").eq("organization_id", orgId).order("created_at", { ascending: false }).limit(8),
        client.from("websites").select("id,domain,status,verified_at,ssl_status,integration_status,last_event_at,created_at").eq("organization_id", orgId).order("created_at", { ascending: true }).limit(20),
        client.from("visitors").select("id,website_id,country,city,device,browser,operating_system,referrer,first_seen_at,last_seen_at").eq("organization_id", orgId).order("last_seen_at", { ascending: false }).limit(100),
        client.from("visitor_sessions").select("id,website_id,visitor_id,requested_url,status,risk_score,occurred_at").eq("organization_id", orgId).order("occurred_at", { ascending: false }).limit(240)
      ]);
      return json({
        metrics: { websites, visitors, activeVisitors, threats, blockedRequests: blocked, openAlerts: alertsCount },
        threats: threatRows.data || [],
        alerts: alertRows.data || [],
        websitesData: websiteRows.data || [],
        visitorsData: visitorRows.data || [],
        sessionsData: sessionRows.data || []
      });
    }

    if (key === "websites") {
      const { data, error } = await client.from("websites").select("id,domain,status,verified_at,ssl_status,integration_status,created_at,updated_at").eq("organization_id", orgId).order("created_at", { ascending: false });
      if (error) throw error;
      return json(data || []);
    }

    if (key === "visitors") {
      const { data, error } = await client.from("visitors").select("id,website_id,visitor_key,ip_address,country,city,device,browser,operating_system,referrer,first_seen_at,last_seen_at").eq("organization_id", orgId).order("last_seen_at", { ascending: false }).limit(200);
      if (error) throw error;
      return json(data || []);
    }

    if (key === "threats") {
      const { data, error } = await client.from("threat_events").select("id,website_id,type,severity,source_ip,target_url,risk_score,status,action_taken,metadata,occurred_at").eq("organization_id", orgId).order("occurred_at", { ascending: false }).limit(200);
      if (error) throw error;
      return json(data || []);
    }

    if (key === "firewall") {
      const [rules, ipRules, countryRules] = await Promise.all([
        client.from("firewall_rules").select("id,website_id,name,priority,enabled,conditions,action,provider_rule_id,created_at,updated_at").eq("organization_id", orgId).order("priority"),
        client.from("ip_rules").select("id,website_id,ip_cidr,action,note,created_at").eq("organization_id", orgId).order("created_at", { ascending: false }),
        client.from("country_rules").select("id,website_id,country_code,action,created_at").eq("organization_id", orgId).order("created_at", { ascending: false })
      ]);
      if (rules.error) throw rules.error;
      if (ipRules.error) throw ipRules.error;
      if (countryRules.error) throw countryRules.error;
      return json({ rules: rules.data || [], ipRules: ipRules.data || [], countryRules: countryRules.data || [], enforcementConnected: (rules.data || []).some((r: any) => Boolean(r.provider_rule_id)) });
    }

    if (key === "analytics" || key === "reports") {
      const [visitors, sessions, threats, blocked] = await Promise.all([
        countRows(client, "visitors", orgId),
        countRows(client, "visitor_sessions", orgId),
        countRows(client, "threat_events", orgId),
        countRows(client, "visitor_sessions", orgId, q => q.eq("status", "BLOCKED"))
      ]);
      return json({ visitors, sessions, threats, blockedRequests: blocked, generatedAt: new Date().toISOString(), formats: key === "reports" ? ["dashboard","csv"] : undefined });
    }

    if (key === "alerts") {
      const { data, error } = await client.from("alerts").select("id,website_id,type,severity,title,message,acknowledged_at,created_at").eq("organization_id", orgId).order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return json(data || []);
    }

    if (key === "billing") {
      const { data, error } = await client.from("subscriptions").select("id,status,current_period_start,current_period_end,plans(code,name,website_limit,monthly_visitor_limit,security_event_limit,retention_days,api_access,reports_access,team_member_limit)").eq("organization_id", orgId).maybeSingle();
      if (error) throw error;
      return json(data || null);
    }

    if (key === "support") {
      const { data, error } = await client.from("support_tickets").select("id,subject,description,priority,status,created_at,updated_at").eq("organization_id", orgId).order("created_at", { ascending: false });
      if (error) throw error;
      return json(data || []);
    }

    if (key === "admin") {
      const [websites, threats, openAlerts, tickets] = await Promise.all([
        countRows(client, "websites", orgId),
        countRows(client, "threat_events", orgId),
        countRows(client, "alerts", orgId, q => q.is("acknowledged_at", null)),
        countRows(client, "support_tickets", orgId, q => q.neq("status", "RESOLVED"))
      ]);
      return json({ organizationId: orgId, websites, threats, openAlerts, openTickets: tickets });
    }

    return json({ code: "NOT_FOUND", message: "Unknown API resource." }, 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Database query failed.";
    return json({ code: "DATABASE_ERROR", message }, 500);
  }
}

export async function POST(request: NextRequest, context: { params: Promise<{ resource: string[] }> }) {
  const user = await getCurrentUser();
  if (!user) return json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
  if (user.demo) return json({ code: "REAL_ACCOUNT_REQUIRED", message: "Use a real registered account for backend write operations." }, 409, { demo: true });
  if (!user.organizationId || user.organizationId === "unassigned") return json({ code: "NO_WORKSPACE", message: "No WebShield workspace is assigned to this account." }, 409);

  const { resource } = await context.params;
  const key = resource[0] || "";
  if (!resources.has(key)) return json({ code: "NOT_FOUND", message: "Unknown API resource." }, 404);
  if (!request.headers.get("content-type")?.includes("application/json")) return json({ code: "INVALID_CONTENT_TYPE", message: "application/json required." }, 415);
  const body = await request.json().catch(() => null) as Record<string, any> | null;
  if (!body || Array.isArray(body)) return json({ code: "INVALID_BODY", message: "A JSON object is required." }, 400);

  const client = await createClient();
  const orgId = user.organizationId;

  try {
    if (key === "websites") {
      if (!body.domain || typeof body.domain !== "string") return json({ code: "INVALID_DOMAIN", message: "domain is required." }, 400);
      const domain = normalizeDomain(body.domain);
      if (!domain || !domain.includes(".")) return json({ code: "INVALID_DOMAIN", message: "Enter a valid website domain." }, 400);
      const { data: existing, error: existingError } = await client.from("websites").select("id,domain,status,ssl_status,integration_status,verified_at,created_at").eq("organization_id", orgId).eq("domain", domain).maybeSingle();
      if (existingError) throw existingError;
      if (existing) return json(existing, 200, { reused: true });
      const { data, error } = await client.from("websites").insert({ organization_id: orgId, domain, status: "VERIFICATION_REQUIRED", ssl_status: "UNKNOWN", integration_status: "NOT_CONNECTED" }).select("id,domain,status,ssl_status,integration_status,created_at").single();
      if (error) throw error;
      return json(data, 201, { reused: false });
    }

    if (key === "firewall") {
      if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
      if (!body.name || !["ALLOW","BLOCK","CHALLENGE","RATE_LIMIT"].includes(body.action)) return json({ code: "INVALID_RULE", message: "name and a valid action are required." }, 400);
      const { data, error } = await client.from("firewall_rules").insert({ organization_id: orgId, website_id: body.websiteId || null, name: String(body.name), priority: Number(body.priority || 100), enabled: body.enabled !== false, conditions: Array.isArray(body.conditions) ? body.conditions : [], action: body.action, created_by: user.id }).select("*").single();
      if (error) throw error;
      return json(data, 201, { enforcement: data.provider_rule_id ? "provider_connected" : "stored_only" });
    }

    if (key === "alerts" && body.id) {
      const { data, error } = await client.from("alerts").update({ acknowledged_at: new Date().toISOString() }).eq("organization_id", orgId).eq("id", body.id).select("*").single();
      if (error) throw error;
      return json(data);
    }

    if (key === "support") {
      if (!body.subject) return json({ code: "INVALID_TICKET", message: "subject is required." }, 400);
      const { data, error } = await client.from("support_tickets").insert({ organization_id: orgId, created_by: user.id, subject: String(body.subject), description: body.description ? String(body.description) : null, priority: body.priority || "MEDIUM" }).select("*").single();
      if (error) throw error;
      return json(data, 201);
    }

    return json({ code: "WRITE_NOT_SUPPORTED", message: `No write operation is defined for ${key}.` }, 405);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Database write failed.";
    return json({ code: "DATABASE_ERROR", message }, 500);
  }
}

export async function DELETE(request: NextRequest, context: { params: Promise<{ resource: string[] }> }) {
  const user = await getCurrentUser();
  if (!user) return json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
  if (user.demo) return json({ code: "REAL_ACCOUNT_REQUIRED", message: "Use a real registered account for backend write operations." }, 409, { demo: true });
  if (!user.organizationId || user.organizationId === "unassigned") return json({ code: "NO_WORKSPACE", message: "No WebShield workspace is assigned to this account." }, 409);

  const { resource } = await context.params;
  const key = resource[0] || "";
  if (key !== "websites") return json({ code: "DELETE_NOT_SUPPORTED", message: "Delete is only available for websites." }, 405);
  if (!["OWNER","ADMIN"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Owner or admin role required." }, 403);

  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return json({ code: "INVALID_ID", message: "Website id is required." }, 400);

  const client = await createClient();
  try {
    const { data: site, error: lookupError } = await client.from("websites").select("id,domain,status,integration_status").eq("organization_id", user.organizationId).eq("id", id).maybeSingle();
    if (lookupError) throw lookupError;
    if (!site) return json({ code: "NOT_FOUND", message: "Website not found." }, 404);
    const { error } = await client.from("websites").delete().eq("organization_id", user.organizationId).eq("id", id);
    if (error) throw error;
    return json({ id: site.id, domain: site.domain, removed: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Website removal failed.";
    return json({ code: "DATABASE_ERROR", message }, 500);
  }
}
