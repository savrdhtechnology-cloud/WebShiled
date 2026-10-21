import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";
import { isValidCidr } from "@/lib/security-engine/request-analysis";

const resources = new Set(["dashboard","websites","visitors","threats","firewall","analytics","reports","alerts","billing","admin","support","scans","alert-channels","uptime"]);
const LEGACY_WEBSITE_COLUMNS = "id,domain,status,verified_at,ssl_status,integration_status,created_at,updated_at,last_event_at";
const LEGACY_ALERT_COLUMNS = "id,website_id,type,severity,title,message,acknowledged_at,created_at";
// Until migration 0006 is applied, fall back to the older column set instead of failing the page.
function missingColumn(error: unknown) { return (error as { code?: string })?.code === "42703"; }
const WEBSITE_COLUMNS = "id,domain,status,verified_at,ssl_status,integration_status,created_at,updated_at,last_event_at,monitoring_enabled,monitoring_interval_minutes,security_score,security_grade,overall_risk,last_scan_at,next_scan_at,uptime_status,last_uptime_check_at,last_response_ms,last_status_code,ssl_expires_at,ssl_issuer,last_ingest_at,ingest_secret_hint";

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
        client.from("websites").select(WEBSITE_COLUMNS).eq("organization_id", orgId).order("created_at", { ascending: true }).limit(20).then(async r => missingColumn(r.error) ? await client.from("websites").select(LEGACY_WEBSITE_COLUMNS).eq("organization_id", orgId).order("created_at", { ascending: true }).limit(20) : r),
        client.from("visitors").select("id,website_id,ip_address,country,city,device,browser,operating_system,referrer,first_seen_at,last_seen_at").eq("organization_id", orgId).order("last_seen_at", { ascending: false }).limit(1000),
        client.from("visitor_sessions").select("id,website_id,visitor_id,requested_url,status,risk_score,occurred_at").eq("organization_id", orgId).order("occurred_at", { ascending: false }).limit(5000)
      ]);
      for (const result of [threatRows,alertRows,websiteRows,visitorRows,sessionRows]) { if(result.error) throw result.error; }
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
      const websitesQuery = (columns: string) => client.from("websites").select(columns).eq("organization_id", orgId).order("created_at", { ascending: false });
      let result: { data: unknown; error: unknown } = await websitesQuery(WEBSITE_COLUMNS);
      if (result.error && missingColumn(result.error)) result = await websitesQuery(LEGACY_WEBSITE_COLUMNS);
      if (result.error) throw result.error;
      const data = result.data as unknown[] | null;
      return json(data || []);
    }

    if (key === "scans") {
      const websiteId = _.nextUrl.searchParams.get("websiteId");
      let query = client.from("security_scan_runs").select("id,website_id,status,security_score,security_grade,overall_risk,finding_counts,findings,started_at,completed_at,created_at,websites(domain)").eq("organization_id", orgId).order("created_at", { ascending: false }).limit(websiteId ? 10 : 30);
      if (websiteId) query = query.eq("website_id", websiteId);
      const { data, error } = await query;
      if (error) throw error;
      return json(data || []);
    }

    if (key === "uptime") {
      const websiteId = _.nextUrl.searchParams.get("websiteId");
      let query = client.from("uptime_checks").select("id,website_id,ok,status_code,response_ms,ssl_days_left,error,checked_at").eq("organization_id", orgId).order("checked_at", { ascending: false }).limit(200);
      if (websiteId) query = query.eq("website_id", websiteId);
      const { data, error } = await query;
      if (error) throw error;
      return json(data || []);
    }

    if (key === "alert-channels") {
      const { data, error } = await client.from("alert_channels").select("enabled,email_recipients,webhook_url,min_severity,updated_at").eq("organization_id", orgId).maybeSingle();
      if (error) throw error;
      return json(data || { enabled: true, email_recipients: [], webhook_url: null, min_severity: "HIGH", defaultOwners: true });
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
        client.from("ip_rules").select("id,website_id,ip_cidr,action,note,expires_at,created_at").eq("organization_id", orgId).order("created_at", { ascending: false }),
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
      const alertsQuery = (columns: string) => client.from("alerts").select(columns).eq("organization_id", orgId).order("created_at", { ascending: false }).limit(200);
      let result: { data: unknown; error: unknown } = await alertsQuery("id,website_id,connection_id,type,severity,title,message,source,occurrences,last_seen_at,acknowledged_at,created_at,metadata");
      if (result.error && missingColumn(result.error)) result = await alertsQuery(LEGACY_ALERT_COLUMNS);
      if (result.error) throw result.error;
      const data = result.data as unknown[] | null;
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
      const [websites, threats, openAlerts, tickets, websiteRows, threatRows, alertRows, visitors, sessions] = await Promise.all([
        countRows(client, "websites", orgId),
        countRows(client, "threat_events", orgId),
        countRows(client, "alerts", orgId, q => q.is("acknowledged_at", null)),
        countRows(client, "support_tickets", orgId, q => q.neq("status", "RESOLVED")),
        client.from("websites").select("id,domain,status,verified_at,ssl_status,integration_status,last_event_at,created_at,updated_at").eq("organization_id", orgId).order("created_at", { ascending: false }).limit(50),
        client.from("threat_events").select("id,website_id,type,severity,source_ip,target_url,risk_score,status,action_taken,occurred_at").eq("organization_id", orgId).order("occurred_at", { ascending: false }).limit(12),
        client.from("alerts").select("id,website_id,type,severity,title,message,acknowledged_at,created_at").eq("organization_id", orgId).order("created_at", { ascending: false }).limit(12),
        countRows(client, "visitors", orgId),
        countRows(client, "visitor_sessions", orgId)
      ]);
      return json({
        organizationId: orgId,
        websites,
        threatsCount: threats,
        openAlerts,
        openTickets: tickets,
        visitors,
        sessions,
        websitesData: websiteRows.data || [],
        threats: threatRows.data || [],
        alerts: alertRows.data || []
      });
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
    if (key === "websites" && body.action === "monitoring") {
      if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const interval = Math.max(15, Math.min(10080, Number(body.intervalMinutes || 1440)));
      const { data, error } = await client.from("websites").update({ monitoring_enabled: body.enabled !== false, monitoring_interval_minutes: interval, updated_at: new Date().toISOString() }).eq("organization_id", orgId).eq("id", String(body.id || "")).select("id,monitoring_enabled,monitoring_interval_minutes").maybeSingle();
      if (error) throw error;
      if (!data) return json({ code: "NOT_FOUND", message: "Website not found." }, 404);
      return json(data);
    }

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

    if (key === "firewall" && body.kind === "ip") {
      if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const cidr = String(body.ip || "").trim();
      if (!isValidCidr(cidr)) return json({ code: "INVALID_IP", message: "Enter a valid IP address or CIDR range, e.g. 203.0.113.7 or 203.0.113.0/24." }, 400);
      if (!["ALLOW","BLOCK","CHALLENGE","RATE_LIMIT"].includes(body.action)) return json({ code: "INVALID_ACTION", message: "A valid action is required." }, 400);
      const hours = Number(body.expiresInHours || 0);
      const { data, error } = await client.from("ip_rules").insert({ organization_id: orgId, website_id: body.websiteId || null, ip_cidr: cidr, action: body.action, note: body.note ? String(body.note).slice(0, 300) : null, created_by: user.id, expires_at: hours > 0 ? new Date(Date.now() + Math.min(hours, 8760) * 3600000).toISOString() : null }).select("*").single();
      if (error) throw error;
      return json(data, 201, { enforcement: "server_ingest" });
    }

    if (key === "alert-channels") {
      if (!["OWNER","ADMIN"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Owner or admin role required." }, 403);
      const emails = (Array.isArray(body.emails) ? body.emails : String(body.emails || "").split(/[\s,;]+/)).map((e: unknown) => String(e).trim().toLowerCase()).filter(Boolean);
      if (emails.some((e: string) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) || emails.length > 10) return json({ code: "INVALID_EMAILS", message: "Enter up to 10 valid email addresses." }, 400);
      const webhook = String(body.webhookUrl || "").trim();
      if (webhook && !/^https:\/\/[^\s]+$/i.test(webhook)) return json({ code: "INVALID_WEBHOOK", message: "Webhook URL must start with https://" }, 400);
      if (!["LOW","MEDIUM","HIGH","CRITICAL"].includes(body.minSeverity || "HIGH")) return json({ code: "INVALID_SEVERITY", message: "Invalid minimum severity." }, 400);
      const { data, error } = await client.from("alert_channels").upsert({ organization_id: orgId, enabled: body.enabled !== false, email_recipients: emails, webhook_url: webhook || null, min_severity: body.minSeverity || "HIGH", updated_at: new Date().toISOString() }).select("enabled,email_recipients,webhook_url,min_severity,updated_at").single();
      if (error) throw error;
      return json(data);
    }

    if (key === "firewall") {
      if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
      if (!body.name || !["ALLOW","BLOCK","CHALLENGE","RATE_LIMIT"].includes(body.action)) return json({ code: "INVALID_RULE", message: "name and a valid action are required." }, 400);
      const { data, error } = await client.from("firewall_rules").insert({ organization_id: orgId, website_id: body.websiteId || null, name: String(body.name), priority: Number(body.priority || 100), enabled: body.enabled !== false, conditions: Array.isArray(body.conditions) ? body.conditions : [], action: body.action, created_by: user.id }).select("*").single();
      if (error) throw error;
      return json(data, 201, { enforcement: data.provider_rule_id ? "provider_connected" : "stored_only" });
    }

    if (key === "alerts" && body.id) {
      if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const { data, error } = await client.from("alerts").update({ acknowledged_at: new Date().toISOString(), acknowledged_by: user.id }).eq("organization_id", orgId).eq("id", body.id).select("*").maybeSingle();
      if (error) throw error;
      if (!data) return json({ code: "NOT_FOUND", message: "Alert not found or not permitted." }, 404);
      return json(data);
    }

    if (key === "support") {
      if (!["LOW","MEDIUM","HIGH"].includes(body.priority || "MEDIUM")) return json({code:"INVALID_PRIORITY",message:"Valid priority required."},400);
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
  if (key === "firewall") {
    if (!["OWNER","ADMIN","SECURITY_ANALYST"].includes(user.role)) return json({ code: "FORBIDDEN", message: "Security role required." }, 403);
    const id = request.nextUrl.searchParams.get("id") || "";
    const table = request.nextUrl.searchParams.get("kind") === "ip" ? "ip_rules" : "firewall_rules";
    const client = await createClient();
    const { data, error } = await client.from(table).delete().eq("organization_id", user.organizationId).eq("id", id).select("id").maybeSingle();
    if (error) return json({ code: "DATABASE_ERROR", message: error.message }, 500);
    if (!data) return json({ code: "NOT_FOUND", message: "Rule not found." }, 404);
    return json({ id, removed: true });
  }
  if (key !== "websites") return json({ code: "DELETE_NOT_SUPPORTED", message: "Delete is only available for websites and firewall rules." }, 405);
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

export async function PATCH(request:NextRequest,context:{params:Promise<{resource:string[]}>}){
 const user=await getCurrentUser();
 if(!user)return json({code:'UNAUTHORIZED',message:'Authentication required.'},401);
 if(user.demo||!user.organizationId||user.organizationId==='unassigned')return json({code:'NO_WORKSPACE',message:'A real workspace account is required.'},409);
 if(!['OWNER','ADMIN','SECURITY_ANALYST'].includes(user.role))return json({code:'FORBIDDEN',message:'A security role is required to update records.'},403);
 const {resource}=await context.params;const key=resource[0];
 if(!['threats','support'].includes(key))return json({code:'UNSUPPORTED',message:'This resource does not support status updates.'},405);
 if(!request.headers.get('content-type')?.includes('application/json'))return json({code:'INVALID_CONTENT_TYPE',message:'application/json required.'},415);
 const body=await request.json().catch(()=>null);
 if(!body||typeof body.id!=='string'||!['OPEN','RESOLVED'].includes(body.status))return json({code:'INVALID_UPDATE',message:'An id and valid status are required.'},400);
 const client=await createClient();
 const {data,error}=await client.from(key==='threats'?'threat_events':'support_tickets').update({status:body.status}).eq('organization_id',user.organizationId).eq('id',body.id).select('id,status').maybeSingle();
 if(error)return json({code:'DATABASE_ERROR',message:error.message},500);
 if(!data)return json({code:'NOT_FOUND',message:'Record not found in this workspace.'},404);
 return json(data);
}
