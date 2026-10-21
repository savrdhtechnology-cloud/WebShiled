import "server-only";

import { decryptSecret } from "@/lib/database-security/crypto";
import { runSupabaseDatabaseAudit } from "@/lib/database-security/audit";
import { runReadOnlyQuery, runWriteQuery } from "@/lib/database-security/supabase-management";
import { buildGuardAlerts, classifyChanges, guardInstallSql, guardPollSql, guardStatusSql, guardUninstallSql, GUARD_POLL_LIMIT, type GuardChange } from "@/lib/database-security/guard";
import { raiseAlert, type Db } from "@/lib/monitoring/alerts";

export const CONNECTION_COLUMNS = "id,organization_id,website_id,provider,name,project_ref,encrypted_secret,secret_hint,access_mode,status,last_checked_at,last_error,created_at,updated_at,guard_enabled,guard_installed_at,guard_tables,guard_anon_insert_tables,guard_trusted_db_users,guard_cursor,guard_last_poll_at,guard_last_error,audit_interval_minutes,next_audit_at";

export type ConnectionRow = {
  id: string;
  organization_id: string;
  name: string;
  project_ref: string;
  encrypted_secret: string;
  access_mode: string;
  status: string;
  guard_enabled?: boolean | null;
  guard_tables?: string[] | null;
  guard_anon_insert_tables?: string[] | null;
  guard_trusted_db_users?: string[] | null;
  guard_cursor?: number | string | null;
  audit_interval_minutes?: number | null;
};

export async function loadConnection(db: Db, orgId: string, id: string): Promise<ConnectionRow> {
  const { data, error } = await db.from("database_connections").select(CONNECTION_COLUMNS).eq("organization_id", orgId).eq("id", id).maybeSingle();
  if (error) throw error;
  if (!data) throw new Error("Database connection not found.");
  return data as ConnectionRow;
}

/** Runs the RLS / grants / functions / storage audit and stores findings. */
export async function runDatabaseScan(db: Db, orgId: string, connection: ConnectionRow, options: { alerts?: boolean } = {}) {
  if (connection.status === "DISABLED") throw new Error("This database connection is disabled.");
  const token = decryptSecret(connection.encrypted_secret);
  const { data: scan, error: scanError } = await db.from("database_scans").insert({
    organization_id: orgId,
    connection_id: connection.id,
    status: "RUNNING",
    started_at: new Date().toISOString()
  }).select("id").single();
  if (scanError) throw scanError;

  try {
    const audit = await runSupabaseDatabaseAudit(connection.project_ref, token);
    const { data: previousOpen } = await db.from("database_findings").select("finding_key")
      .eq("organization_id", orgId).eq("connection_id", connection.id).in("status", ["OPEN", "ACCEPTED_RISK"]);
    const { data: hadScan } = await db.from("database_scans").select("id").eq("organization_id", orgId).eq("connection_id", connection.id).eq("status", "COMPLETED").limit(1);
    const known = new Set((previousOpen || []).map(row => String(row.finding_key)));
    const { data: accepted } = await db.from("database_findings").select("finding_key")
      .eq("organization_id", orgId).eq("connection_id", connection.id).eq("status", "ACCEPTED_RISK");
    const acceptedKeys = new Set((accepted || []).map(row => String(row.finding_key)));

    await db.from("database_findings")
      .update({ status: "SUPERSEDED", updated_at: new Date().toISOString() })
      .eq("organization_id", orgId).eq("connection_id", connection.id).eq("status", "OPEN");

    // Accepted risks stay accepted; do not re-open them on every scan.
    const fresh = audit.findings.filter(f => !acceptedKeys.has(f.key));
    if (fresh.length) {
      const { error: findingError } = await db.from("database_findings").insert(fresh.map(f => ({
        organization_id: orgId,
        connection_id: connection.id,
        scan_id: scan.id,
        finding_key: f.key,
        category: f.category,
        severity: f.severity,
        title: f.title,
        description: f.description,
        impact: f.impact,
        evidence: f.evidence,
        recommended_fix: f.recommendedFix,
        fix_type: f.fixType,
        status: "OPEN"
      })));
      if (findingError) throw findingError;
    }

    const completedAt = new Date();
    const interval = Math.max(60, Number(connection.audit_interval_minutes || 1440));
    const { error: completeError } = await db.from("database_scans").update({
      status: "COMPLETED",
      security_score: audit.summary.securityScore,
      overall_risk: audit.summary.overallRisk,
      finding_counts: audit.summary.findingCounts,
      summary: audit.summary,
      completed_at: completedAt.toISOString()
    }).eq("organization_id", orgId).eq("id", scan.id);
    if (completeError) throw completeError;

    await db.from("database_connections").update({
      status: "CONNECTED",
      last_checked_at: completedAt.toISOString(),
      next_audit_at: new Date(completedAt.getTime() + interval * 60000).toISOString(),
      last_error: null,
      updated_at: completedAt.toISOString()
    }).eq("organization_id", orgId).eq("id", connection.id);

    let alerts = 0;
    if (options.alerts !== false && hadScan?.length) {
      for (const f of fresh) {
        if (known.has(f.key) || (f.severity !== "HIGH" && f.severity !== "CRITICAL")) continue;
        const result = await raiseAlert(db, {
          organizationId: orgId,
          connectionId: connection.id,
          type: "DATABASE_FINDING",
          severity: f.severity,
          title: `${connection.name}: ${f.title}`,
          message: `${f.description} ${f.impact} Recommended: ${f.recommendedFix}`,
          source: "database_audit",
          dedupeKey: `dbaudit:${connection.id}:${f.key}`,
          metadata: { category: f.category, evidence: f.evidence, fixType: f.fixType }
        });
        if (result.created) alerts++;
      }
    }
    return { scanId: scan.id as string, alerts, ...audit };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Database scan failed.";
    await db.from("database_scans").update({ status: "FAILED", error_message: message, completed_at: new Date().toISOString() }).eq("organization_id", orgId).eq("id", scan.id);
    await db.from("database_connections").update({ status: "ERROR", last_error: message, last_checked_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("organization_id", orgId).eq("id", connection.id);
    throw error;
  }
}

/** Installs or re-syncs the Data Guard triggers. Requires a REMEDIATION connection. */
export async function installDataGuard(db: Db, orgId: string, connection: ConnectionRow, tables: string[], anonInsertTables: string[], trustedDbUsers: string[]) {
  if (connection.access_mode !== "REMEDIATION") throw new Error("Data Guard installs a trigger in your database. Reconnect with \"Audit + approved remediation\" access first.");
  const token = decryptSecret(connection.encrypted_secret);
  await runWriteQuery(connection.project_ref, token, guardInstallSql(tables));
  const status = await guardStatus(connection.project_ref, token);
  // Start from the current end of the log so historic rows are not re-alerted.
  const tail = await guardRead(connection.project_ref, token, "select coalesce(max(id), 0) as last_id from webshield_guard.change_log;");
  const now = new Date().toISOString();
  const { data, error } = await db.from("database_connections").update({
    guard_enabled: true,
    guard_installed_at: now,
    guard_tables: status.tables,
    guard_anon_insert_tables: anonInsertTables,
    guard_trusted_db_users: trustedDbUsers,
    guard_cursor: Number(tail[0]?.last_id || 0),
    guard_last_error: null,
    updated_at: now
  }).eq("organization_id", orgId).eq("id", connection.id).select("id,guard_enabled,guard_tables,guard_anon_insert_tables,guard_trusted_db_users").single();
  if (error) throw error;
  return data;
}

export async function uninstallDataGuard(db: Db, orgId: string, connection: ConnectionRow) {
  if (connection.access_mode !== "REMEDIATION") throw new Error("Removing Data Guard needs a connection with remediation access.");
  await runWriteQuery(connection.project_ref, decryptSecret(connection.encrypted_secret), guardUninstallSql());
  const { error } = await db.from("database_connections").update({ guard_enabled: false, guard_tables: [], guard_cursor: 0, updated_at: new Date().toISOString() })
    .eq("organization_id", orgId).eq("id", connection.id);
  if (error) throw error;
  return { removed: true };
}

/** Read query for Data Guard objects; falls back to the remediation endpoint if the read-only role cannot see the guard schema. */
async function guardRead(projectRef: string, token: string, sql: string) {
  try { return await runReadOnlyQuery(projectRef, token, sql); }
  catch { return rowsOf(await runWriteQuery(projectRef, token, sql)); }
}

function rowsOf(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) return value as Array<Record<string, unknown>>;
  const nested = value && typeof value === "object" ? (value as Record<string, unknown>).result || (value as Record<string, unknown>).data : null;
  return Array.isArray(nested) ? nested as Array<Record<string, unknown>> : [];
}

export async function guardStatus(projectRef: string, token: string) {
  const rows = await guardRead(projectRef, token, guardStatusSql());
  const row = rows[0] || {};
  const raw = row.watched_tables;
  const tables = Array.isArray(raw) ? raw.map(String) : String(raw || "").replace(/^\{|\}$/g, "").split(",").filter(Boolean);
  return { installed: row.installed === true || row.installed === "true" || row.installed === "t", tables };
}

/** Reads new change-log rows, classifies them, stores activity and raises alerts. */
export async function pollDataGuard(db: Db, orgId: string, connection: ConnectionRow, maxBatches = 4) {
  if (!connection.guard_enabled) return { processed: 0, suspicious: 0, alerts: 0 };
  const token = decryptSecret(connection.encrypted_secret);
  let cursor = Number(connection.guard_cursor || 0);
  let processed = 0, suspicious = 0, alerts = 0;
  try {
    for (let batch = 0; batch < maxBatches; batch++) {
      const rows = await guardRead(connection.project_ref, token, guardPollSql(cursor)) as unknown as GuardChange[];
      if (!rows.length) break;
      const classified = classifyChanges(rows, {
        anonInsertTables: connection.guard_anon_insert_tables || [],
        trustedDbUsers: connection.guard_trusted_db_users || []
      });
      // Keep every suspicious change, and a sample of normal activity for context.
      const keep = classified.filter((c, i) => c.suspicious || i % 10 === 0);
      if (keep.length) {
        const { error } = await db.from("database_activity_events").upsert(keep.map(c => ({
          organization_id: orgId,
          connection_id: connection.id,
          source_id: c.sourceId,
          occurred_at: c.occurred_at,
          table_schema: c.table_schema,
          table_name: c.table_name,
          operation: c.operation,
          db_user: c.db_user,
          jwt_role: c.jwt_role,
          user_id: c.jwt_sub,
          client_ip: c.client_ip,
          row_pk: c.row_pk,
          changed_columns: c.columns,
          suspicious: c.suspicious,
          severity: c.severity,
          reasons: c.reasons.map(r => r.message)
        })), { onConflict: "connection_id,source_id", ignoreDuplicates: true });
        if (error) throw error;
      }
      for (const alert of buildGuardAlerts(connection.id, connection.name, classified)) {
        const result = await raiseAlert(db, {
          organizationId: orgId,
          connectionId: connection.id,
          type: `DATA_GUARD_${alert.code}`,
          severity: alert.severity === "INFO" ? "LOW" : alert.severity,
          title: alert.title,
          message: alert.message,
          source: "data_guard",
          dedupeKey: alert.dedupeKey,
          metadata: { table: alert.table, count: alert.count, actors: alert.actors, ips: alert.ips, firstSeen: alert.firstSeen, lastSeen: alert.lastSeen }
        });
        if (result.created) alerts++;
      }
      processed += rows.length;
      suspicious += classified.filter(c => c.suspicious).length;
      cursor = Math.max(cursor, ...classified.map(c => c.sourceId));
      if (rows.length < GUARD_POLL_LIMIT) break;
    }
    await db.from("database_connections").update({ guard_cursor: cursor, guard_last_poll_at: new Date().toISOString(), guard_last_error: null })
      .eq("organization_id", orgId).eq("id", connection.id);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Data Guard poll failed.";
    await db.from("database_connections").update({ guard_cursor: cursor, guard_last_poll_at: new Date().toISOString(), guard_last_error: message })
      .eq("organization_id", orgId).eq("id", connection.id);
    throw error;
  }
  return { processed, suspicious, alerts };
}
