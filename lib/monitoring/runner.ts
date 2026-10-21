import "server-only";

import { runPassiveScan } from "@/lib/passive-scanner";
import { checkUptime } from "@/lib/monitoring/uptime";
import { persistWebsiteScan, type WebsiteRow } from "@/lib/monitoring/website-scans";
import { raiseAlert, resolveAlert, type Db } from "@/lib/monitoring/alerts";
import { CONNECTION_COLUMNS, pollDataGuard, runDatabaseScan, type ConnectionRow } from "@/lib/database-security/service";

export type CycleOptions = {
  organizationId?: string;
  websiteId?: string;
  /** Run posture scans and database audits even if they are not due yet. */
  force?: boolean;
  /** Stop starting new work after this many milliseconds. */
  budgetMs?: number;
  includeWebsites?: boolean;
  includeDatabases?: boolean;
};

export type CycleReport = {
  startedAt: string;
  finishedAt: string;
  websites: Array<{ id: string; domain: string; uptime?: string; responseMs?: number | null; sslDaysLeft?: number | null; scanned?: boolean; score?: number; error?: string }>;
  databases: Array<{ id: string; name: string; guard?: { processed: number; suspicious: number; alerts: number }; audited?: boolean; error?: string }>;
  alertsCreated: number;
  skipped: number;
};

const DOWN_ALERT_AFTER_FAILURES = 2;

async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>) {
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) await fn(items[index++]);
  });
  await Promise.all(workers);
}

export async function runMonitoringCycle(db: Db, options: CycleOptions = {}): Promise<CycleReport> {
  const started = Date.now();
  const budget = options.budgetMs ?? 240_000;
  const outOfTime = () => Date.now() - started > budget;
  const report: CycleReport = { startedAt: new Date(started).toISOString(), finishedAt: "", websites: [], databases: [], alertsCreated: 0, skipped: 0 };

  if (options.includeWebsites !== false) {
    let query = db.from("websites")
      .select("id,organization_id,domain,monitoring_enabled,monitoring_interval_minutes,last_scan_at,next_scan_at,security_score,last_scan,uptime_status,consecutive_failures")
      .eq("monitoring_enabled", true)
      .order("last_uptime_check_at", { ascending: true, nullsFirst: true })
      .limit(200);
    if (options.organizationId) query = query.eq("organization_id", options.organizationId);
    if (options.websiteId) query = query.eq("id", options.websiteId);
    const { data: sites, error } = await query;
    if (error) throw error;

    await mapLimit(sites || [], 4, async site => {
      if (outOfTime()) { report.skipped++; return; }
      const entry: CycleReport["websites"][number] = { id: site.id, domain: site.domain };
      report.websites.push(entry);
      try {
        // 1. Uptime + TLS certificate
        const up = await checkUptime(site.domain);
        const failures = up.status === "DOWN" ? Number(site.consecutive_failures || 0) + 1 : 0;
        entry.uptime = up.status; entry.responseMs = up.responseMs; entry.sslDaysLeft = up.ssl.daysLeft;
        await db.from("uptime_checks").insert({
          organization_id: site.organization_id, website_id: site.id, ok: up.ok,
          status_code: up.statusCode, response_ms: up.responseMs, ssl_days_left: up.ssl.daysLeft,
          error: up.error || up.ssl.error, checked_at: up.checkedAt
        });
        await db.from("websites").update({
          uptime_status: up.status,
          last_uptime_check_at: up.checkedAt,
          last_response_ms: up.responseMs,
          last_status_code: up.statusCode,
          consecutive_failures: failures,
          ssl_expires_at: up.ssl.expiresAt,
          ssl_issuer: up.ssl.issuer,
          ...(up.ssl.checked ? { ssl_status: up.ssl.valid ? "VALID" : "INVALID" } : {})
        }).eq("organization_id", site.organization_id).eq("id", site.id);

        if (up.status === "DOWN" && failures >= DOWN_ALERT_AFTER_FAILURES) {
          const r = await raiseAlert(db, {
            organizationId: site.organization_id, websiteId: site.id, type: "WEBSITE_DOWN", severity: "CRITICAL",
            title: `${site.domain} is down`,
            message: `${failures} consecutive checks failed. ${up.error || `HTTP ${up.statusCode}`}.`,
            source: "uptime", dedupeKey: `uptime:${site.id}`,
            metadata: { statusCode: up.statusCode, error: up.error, failures }
          });
          if (r.created) report.alertsCreated++;
        } else if (up.status !== "DOWN") {
          await resolveAlert(db, site.organization_id, `uptime:${site.id}`, `Recovered: HTTP ${up.statusCode} in ${up.responseMs} ms`);
        }

        if (up.ssl.checked && !up.ssl.valid) {
          const r = await raiseAlert(db, {
            organizationId: site.organization_id, websiteId: site.id, type: "SSL_INVALID", severity: "HIGH",
            title: `${site.domain}: SSL certificate is not trusted`,
            message: `Browsers will show a security warning. ${up.ssl.error || ""}`.trim(),
            source: "ssl", dedupeKey: `ssl-invalid:${site.id}`, metadata: { issuer: up.ssl.issuer, expiresAt: up.ssl.expiresAt }
          });
          if (r.created) report.alertsCreated++;
        } else if (up.ssl.checked) {
          await resolveAlert(db, site.organization_id, `ssl-invalid:${site.id}`, "Certificate trusted again");
        }
        if (up.ssl.daysLeft !== null && up.ssl.daysLeft <= 14) {
          const r = await raiseAlert(db, {
            organizationId: site.organization_id, websiteId: site.id, type: "SSL_EXPIRING",
            severity: up.ssl.daysLeft <= 3 ? "CRITICAL" : "HIGH",
            title: up.ssl.daysLeft < 0 ? `${site.domain}: SSL certificate expired` : `${site.domain}: SSL certificate expires in ${up.ssl.daysLeft} day(s)`,
            message: `Certificate valid until ${up.ssl.expiresAt}${up.ssl.issuer ? ` (issuer ${up.ssl.issuer})` : ""}. Renew it before visitors see warnings.`,
            source: "ssl", dedupeKey: `ssl-expiry:${site.id}`, metadata: { daysLeft: up.ssl.daysLeft, expiresAt: up.ssl.expiresAt }
          });
          if (r.created) report.alertsCreated++;
        } else if (up.ssl.daysLeft !== null) {
          await resolveAlert(db, site.organization_id, `ssl-expiry:${site.id}`, "Certificate renewed");
        }

        // 2. Passive posture scan when due
        const due = options.force || !site.last_scan_at || !site.next_scan_at || new Date(site.next_scan_at).getTime() <= Date.now();
        if (due && up.status !== "DOWN" && !outOfTime()) {
          const scan = await runPassiveScan(site.domain);
          const saved = await persistWebsiteScan(db, site as WebsiteRow, scan);
          entry.scanned = true; entry.score = scan.securityScore;
          report.alertsCreated += saved.alerts;
        }
      } catch (error) {
        entry.error = error instanceof Error ? error.message : "Monitoring failed.";
      }
    });
  }

  if (options.includeDatabases !== false && !options.websiteId) {
    let query = db.from("database_connections").select(CONNECTION_COLUMNS).neq("status", "DISABLED").limit(100);
    if (options.organizationId) query = query.eq("organization_id", options.organizationId);
    const { data: connections, error } = await query;
    if (error) throw error;
    for (const connection of (connections || []) as unknown as Array<ConnectionRow & { next_audit_at?: string | null }>) {
      if (outOfTime()) { report.skipped++; continue; }
      const entry: CycleReport["databases"][number] = { id: connection.id, name: connection.name };
      report.databases.push(entry);
      try {
        if (connection.guard_enabled) {
          entry.guard = await pollDataGuard(db, connection.organization_id, connection);
          report.alertsCreated += entry.guard.alerts;
        }
        const auditDue = options.force || !connection.next_audit_at || new Date(connection.next_audit_at).getTime() <= Date.now();
        if (auditDue && !outOfTime()) {
          const result = await runDatabaseScan(db, connection.organization_id, connection);
          entry.audited = true;
          report.alertsCreated += result.alerts;
        }
      } catch (error) {
        entry.error = error instanceof Error ? error.message : "Database monitoring failed.";
        const r = await raiseAlert(db, {
          organizationId: connection.organization_id, connectionId: connection.id, type: "DATABASE_MONITORING_FAILED", severity: "MEDIUM",
          title: `${connection.name}: database monitoring failed`,
          message: `${entry.error} Check that the Management API token is still valid.`,
          source: "database_audit", dedupeKey: `dbmon:${connection.id}`
        }).catch(() => null);
        if (r?.created) report.alertsCreated++;
      }
    }
  }

  report.finishedAt = new Date().toISOString();
  return report;
}
