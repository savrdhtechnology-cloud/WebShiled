import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";
import { decryptSecret, encryptSecret, secretHint } from "@/lib/database-security/crypto";
import { remediationSql } from "@/lib/database-security/audit";
import { runReadOnlyQuery, runWriteQuery, validateProjectRef, verifySupabaseDatabaseAccess } from "@/lib/database-security/supabase-management";
import { LIST_TABLES_SQL, normalizeDbUsers, normalizeTableList, suggestGuardTables } from "@/lib/database-security/guard";
import { installDataGuard, loadConnection, pollDataGuard, runDatabaseScan, uninstallDataGuard } from "@/lib/database-security/service";

function reply(data: unknown, status = 200) {
  return NextResponse.json({ ok: status < 400, data: status < 400 ? data : null, error: status >= 400 ? data : null }, { status });
}

function setupRequired(error: unknown) {
  const value = error as { code?: string; message?: string };
  return value?.code === "42P01" || value?.code === "42703" || /database_(connections|scans|findings)|remediation_jobs|relation .* does not exist|column .* does not exist/i.test(value?.message || "");
}

async function context() {
  const user = await getCurrentUser();
  if (!user) return { error: reply({ code: "UNAUTHORIZED", message: "Authentication required." }, 401) };
  if (user.demo) return { error: reply({ code: "REAL_ACCOUNT_REQUIRED", message: "Use a real WebShield account for Database Security." }, 409) };
  if (!user.organizationId || user.organizationId === "unassigned") return { error: reply({ code: "NO_WORKSPACE", message: "No WebShield workspace is assigned." }, 409) };
  return { user, client: await createClient(), orgId: user.organizationId };
}

function canScan(role: string) {
  return ["OWNER","ADMIN","SECURITY_ANALYST"].includes(role);
}
function canManage(role: string) {
  return ["OWNER","ADMIN"].includes(role);
}

export async function GET(request: NextRequest) {
  const ctx = await context();
  if ("error" in ctx) return ctx.error;
  const { client, orgId } = ctx;
  const requested = request.nextUrl.searchParams.get("connectionId");

  try {
    const [connections, scans, findings, jobs] = await Promise.all([
      client.from("database_connections")
        .select("id,website_id,provider,name,project_ref,secret_hint,access_mode,status,last_checked_at,last_error,created_at,updated_at,guard_enabled,guard_installed_at,guard_tables,guard_anon_insert_tables,guard_trusted_db_users,guard_last_poll_at,guard_last_error,audit_interval_minutes,next_audit_at")
        .eq("organization_id", orgId)
        .order("created_at", { ascending: false }),
      client.from("database_scans")
        .select("id,connection_id,status,security_score,overall_risk,finding_counts,summary,started_at,completed_at,error_message,created_at")
        .eq("organization_id", orgId)
        .order("created_at", { ascending: false })
        .limit(100),
      client.from("database_findings")
        .select("id,connection_id,scan_id,finding_key,category,severity,title,description,impact,evidence,recommended_fix,fix_type,status,created_at,updated_at")
        .eq("organization_id", orgId)
        .in("status", ["OPEN","ACCEPTED_RISK"])
        .order("created_at", { ascending: false })
        .limit(300),
      client.from("remediation_jobs")
        .select("id,connection_id,finding_id,action_type,proposed_change,status,result,approved_at,applied_at,created_at")
        .eq("organization_id", orgId)
        .order("created_at", { ascending: false })
        .limit(100)
    ]);

    for (const result of [connections, scans, findings, jobs]) if (result.error) throw result.error;
    const firstId = requested || connections.data?.[0]?.id || null;
    let activity: unknown[] = [];
    if (firstId) {
      const { data: events, error: activityError } = await client.from("database_activity_events")
        .select("id,connection_id,occurred_at,table_schema,table_name,operation,db_user,jwt_role,user_id,client_ip,row_pk,changed_columns,suspicious,severity,reasons,reviewed_at")
        .eq("organization_id", orgId).eq("connection_id", firstId)
        .order("occurred_at", { ascending: false }).limit(200);
      // Older deployments without migration 0006 simply show no activity.
      if (!activityError) activity = events || [];
    }

    const connectionRows = connections.data || [];
    const latestByConnection = new Map<string, unknown>();
    for (const scan of scans.data || []) if (!latestByConnection.has(scan.connection_id)) latestByConnection.set(scan.connection_id, scan);

    const selectedId = requested || connectionRows[0]?.id || null;
    return reply({
      setupRequired: false,
      connections: connectionRows.map(row => ({ ...row, latestScan: latestByConnection.get(row.id) || null })),
      selectedConnectionId: selectedId,
      findings: (findings.data || []).filter(row => !selectedId || row.connection_id === selectedId),
      remediationJobs: (jobs.data || []).filter(row => !selectedId || row.connection_id === selectedId),
      activity
    });
  } catch (error) {
    if (setupRequired(error)) return reply({
      setupRequired: true,
      message: "Database Security schema is not fully activated. Apply supabase/migrations/0003_database_security.sql and 0006_live_monitoring_and_data_guard.sql in the WebShield Supabase SQL editor.",
      connections: [],
      findings: [],
      remediationJobs: [],
      activity: []
    });
    const message = error instanceof Error ? error.message : "Database Security could not be loaded.";
    return reply({ code: "DATABASE_SECURITY_ERROR", message }, 500);
  }
}

export async function POST(request: NextRequest) {
  const ctx = await context();
  if ("error" in ctx) return ctx.error;
  const { user, client, orgId } = ctx;
  if (!request.headers.get("content-type")?.includes("application/json")) return reply({ code: "INVALID_CONTENT_TYPE", message: "application/json required." }, 415);
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return reply({ code: "INVALID_BODY", message: "A JSON object is required." }, 400);
  const action = String(body.action || "");

  try {
    if (action === "connect") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin role required to connect a database." }, 403);
      const provider = String(body.provider || "SUPABASE").toUpperCase();
      if (provider !== "SUPABASE") return reply({ code: "PROVIDER_NOT_SUPPORTED", message: "Supabase is the first supported database provider." }, 400);
      const projectRef = validateProjectRef(String(body.projectRef || ""));
      const token = String(body.accessToken || "").trim();
      if (token.length < 20) return reply({ code: "INVALID_TOKEN", message: "A scoped Supabase Management API token is required." }, 400);
      await verifySupabaseDatabaseAccess(projectRef, token);

      const payload = {
        organization_id: orgId,
        website_id: body.websiteId ? String(body.websiteId) : null,
        provider: "SUPABASE",
        name: String(body.name || "Supabase Database").trim().slice(0, 120),
        project_ref: projectRef,
        endpoint_url: `https://${projectRef}.supabase.co`,
        encrypted_secret: encryptSecret(token),
        secret_hint: secretHint(token),
        access_mode: body.accessMode === "REMEDIATION" ? "REMEDIATION" : "READ_ONLY",
        status: "CONNECTED",
        last_checked_at: new Date().toISOString(),
        last_error: null,
        created_by: user.id,
        updated_at: new Date().toISOString()
      };
      const { data, error } = await client
        .from("database_connections")
        .upsert(payload, { onConflict: "organization_id,provider,project_ref" })
        .select("id,website_id,provider,name,project_ref,secret_hint,access_mode,status,last_checked_at,last_error,created_at,updated_at")
        .single();
      if (error) throw error;
      return reply(data, 201);
    }

    if (action === "scan") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security analyst, admin or owner role required." }, 403);
      const connection = await loadConnection(client, orgId, String(body.connectionId || ""));
      if (connection.status === "DISABLED") return reply({ code: "CONNECTION_DISABLED", message: "This database connection is disabled." }, 409);
      const result = await runDatabaseScan(client, orgId, connection);
      return reply(result);
    }

    if (action === "list_tables") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const connection = await loadConnection(client, orgId, String(body.connectionId || ""));
      const rows = await runReadOnlyQuery(connection.project_ref, decryptSecret(connection.encrypted_secret), LIST_TABLES_SQL);
      return reply({
        tables: rows.map(r => ({ table: `${String(r.schema_name)}.${String(r.table_name)}`, rlsEnabled: r.rls_enabled === true || r.rls_enabled === "t", approxRows: Number(r.approx_rows || 0) })),
        suggested: suggestGuardTables(rows)
      });
    }

    if (action === "install_guard") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin approval is required to install Data Guard." }, 403);
      const connection = await loadConnection(client, orgId, String(body.connectionId || ""));
      const tables = normalizeTableList(body.tables);
      const anonInsert = normalizeTableList(body.anonInsertTables || []);
      const trusted = normalizeDbUsers(body.trustedDbUsers || []);
      const data = await installDataGuard(client, orgId, connection, tables, anonInsert, trusted);
      return reply(data);
    }

    if (action === "update_guard_rules") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin role required." }, 403);
      const id = String(body.connectionId || "");
      await loadConnection(client, orgId, id);
      const { data, error } = await client.from("database_connections").update({
        guard_anon_insert_tables: normalizeTableList(body.anonInsertTables || []),
        guard_trusted_db_users: normalizeDbUsers(body.trustedDbUsers || []),
        ...(body.auditIntervalMinutes ? { audit_interval_minutes: Math.max(60, Math.min(10080, Number(body.auditIntervalMinutes) || 1440)) } : {}),
        updated_at: new Date().toISOString()
      }).eq("organization_id", orgId).eq("id", id).select("id,guard_anon_insert_tables,guard_trusted_db_users,audit_interval_minutes").single();
      if (error) throw error;
      return reply(data);
    }

    if (action === "uninstall_guard") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin role required." }, 403);
      const connection = await loadConnection(client, orgId, String(body.connectionId || ""));
      return reply(await uninstallDataGuard(client, orgId, connection));
    }

    if (action === "poll_guard") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const connection = await loadConnection(client, orgId, String(body.connectionId || ""));
      if (!connection.guard_enabled) return reply({ code: "GUARD_NOT_INSTALLED", message: "Install Data Guard on this database first." }, 409);
      return reply(await pollDataGuard(client, orgId, connection));
    }

    if (action === "review_activity") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const { data, error } = await client.from("database_activity_events").update({ reviewed_at: new Date().toISOString() })
        .eq("organization_id", orgId).eq("id", String(body.eventId || "")).select("id,reviewed_at").single();
      if (error) throw error;
      return reply(data);
    }

    if (action === "preview_fix") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const findingId = String(body.findingId || "");
      const { data: finding, error } = await client.from("database_findings")
        .select("id,connection_id,fix_type,evidence,title,severity,status")
        .eq("organization_id", orgId).eq("id", findingId).maybeSingle();
      if (error) throw error;
      if (!finding) return reply({ code: "NOT_FOUND", message: "Finding not found." }, 404);
      const sql = remediationSql(finding);
      return reply({
        findingId,
        title: finding.title,
        severity: finding.severity,
        fixType: finding.fix_type,
        sql,
        warning: "Database changes can affect application behavior. Review the SQL and application access requirements before applying."
      });
    }

    if (action === "apply_fix") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin approval is required to change a database." }, 403);
      const findingId = String(body.findingId || "");
      const { data: finding, error } = await client.from("database_findings")
        .select("id,connection_id,fix_type,evidence,title,severity,status")
        .eq("organization_id", orgId).eq("id", findingId).maybeSingle();
      if (error) throw error;
      if (!finding) return reply({ code: "NOT_FOUND", message: "Finding not found." }, 404);
      if (finding.status !== "OPEN") return reply({ code: "NOT_OPEN", message: "Only open findings can be remediated." }, 409);

      const connection = await loadConnection(client, orgId, finding.connection_id);
      if (connection.access_mode !== "REMEDIATION") return reply({ code: "READ_ONLY_CONNECTION", message: "Reconnect this database with Remediation access before applying changes." }, 409);
      const sql = remediationSql(finding);
      const { data: job, error: jobError } = await client.from("remediation_jobs").insert({
        organization_id: orgId,
        connection_id: connection.id,
        finding_id: finding.id,
        action_type: finding.fix_type,
        proposed_change: { sql },
        status: "APPROVED",
        approved_by: user.id,
        approved_at: new Date().toISOString()
      }).select("id").single();
      if (jobError) throw jobError;

      try {
        const result = await runWriteQuery(connection.project_ref, decryptSecret(connection.encrypted_secret), sql);
        const now = new Date().toISOString();
        await client.from("remediation_jobs").update({
          status: "APPLIED",
          applied_by: user.id,
          applied_at: now,
          result: { provider: "SUPABASE", applied: true }
        }).eq("organization_id", orgId).eq("id", job.id);
        await client.from("database_findings").update({ status: "FIXED", updated_at: now }).eq("organization_id", orgId).eq("id", finding.id);
        return reply({ jobId: job.id, findingId: finding.id, applied: true, providerResult: result });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Remediation failed.";
        await client.from("remediation_jobs").update({ status: "FAILED", result: { message } }).eq("organization_id", orgId).eq("id", job.id);
        throw error;
      }
    }

    if (action === "accept_risk") {
      if (!canScan(user.role)) return reply({ code: "FORBIDDEN", message: "Security role required." }, 403);
      const findingId = String(body.findingId || "");
      const { data, error } = await client.from("database_findings").update({
        status: "ACCEPTED_RISK",
        updated_at: new Date().toISOString()
      }).eq("organization_id", orgId).eq("id", findingId).select("id,status").single();
      if (error) throw error;
      return reply(data);
    }

    if (action === "disconnect") {
      if (!canManage(user.role)) return reply({ code: "FORBIDDEN", message: "Owner or admin role required." }, 403);
      const id = String(body.connectionId || "");
      const { error } = await client.from("database_connections").delete().eq("organization_id", orgId).eq("id", id);
      if (error) throw error;
      return reply({ id, disconnected: true });
    }

    return reply({ code: "UNKNOWN_ACTION", message: "Unknown Database Security action." }, 400);
  } catch (error) {
    if (setupRequired(error)) return reply({ code: "SCHEMA_REQUIRED", message: "Database Security schema must be activated before this feature can store connections and scan results." }, 409);
    const message = error instanceof Error ? error.message : "Database Security request failed.";
    return reply({ code: "DATABASE_SECURITY_ERROR", message }, 500);
  }
}
