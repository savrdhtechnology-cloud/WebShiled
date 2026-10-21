import "server-only";

import { runPassiveScan } from "@/lib/passive-scanner";
import { raiseAlert, type Db } from "@/lib/monitoring/alerts";

type Scan = Awaited<ReturnType<typeof runPassiveScan>>;
export type WebsiteRow = {
  id: string;
  organization_id: string;
  domain: string;
  security_score?: number | null;
  last_scan?: { findings?: Array<{ title?: string; severity?: string }> } | null;
  monitoring_interval_minutes?: number | null;
};

/** Stores a completed passive scan for a website and raises alerts for regressions. */
export async function persistWebsiteScan(db: Db, site: WebsiteRow, scan: Scan, options: { alerts?: boolean } = {}) {
  const now = new Date();
  const interval = Math.max(15, Number(site.monitoring_interval_minutes || 1440));
  const { data: run, error: runError } = await db.from("security_scan_runs").insert({
    organization_id: site.organization_id,
    website_id: site.id,
    status: "COMPLETED",
    security_score: scan.securityScore,
    security_grade: scan.grade,
    overall_risk: scan.overallRisk,
    finding_counts: scan.findingCounts,
    findings: scan.findings,
    scan_payload: scan,
    started_at: scan.scannedAt,
    completed_at: now.toISOString()
  }).select("id").single();
  if (runError) throw runError;

  const { error: siteError } = await db.from("websites").update({
    security_score: scan.securityScore,
    security_grade: scan.grade,
    overall_risk: scan.overallRisk,
    last_scan_at: now.toISOString(),
    next_scan_at: new Date(now.getTime() + interval * 60000).toISOString(),
    last_scan: { findings: scan.findings, findingCounts: scan.findingCounts, finalUrl: scan.finalUrl, status: scan.status, scannedAt: scan.scannedAt },
    ssl_status: scan.https ? "VALID" : "NOT_HTTPS",
    updated_at: now.toISOString()
  }).eq("organization_id", site.organization_id).eq("id", site.id);
  if (siteError) throw siteError;

  let alerts = 0;
  if (options.alerts !== false) {
    const previous = new Set((site.last_scan?.findings || []).map(f => String(f.title || "")));
    const hadPrevious = Array.isArray(site.last_scan?.findings);
    for (const finding of scan.findings) {
      const severe = finding.severity === "CRITICAL" || finding.severity === "HIGH";
      // On the very first scan only CRITICAL findings alert; afterwards any new HIGH+ finding does.
      if (!severe || (hadPrevious && previous.has(finding.title)) || (!hadPrevious && finding.severity !== "CRITICAL")) continue;
      const result = await raiseAlert(db, {
        organizationId: site.organization_id,
        websiteId: site.id,
        type: "WEBSITE_FINDING",
        severity: finding.severity,
        title: `${site.domain}: ${finding.title}`,
        message: `${finding.detail} ${finding.impact} Fix: ${finding.fix}`,
        source: "scan",
        dedupeKey: `scan:${site.id}:${finding.title}`,
        metadata: { category: finding.category, scanRunId: run.id }
      });
      if (result.created) alerts++;
    }
    const before = typeof site.security_score === "number" ? site.security_score : null;
    if (before !== null && before - scan.securityScore >= 10) {
      const result = await raiseAlert(db, {
        organizationId: site.organization_id,
        websiteId: site.id,
        type: "SCORE_DROP",
        severity: before - scan.securityScore >= 25 ? "HIGH" : "MEDIUM",
        title: `${site.domain}: security score dropped ${before} → ${scan.securityScore}`,
        message: `The passive security score fell by ${before - scan.securityScore} points since the previous scan. Review new findings in Websites & Scan.`,
        source: "scan",
        dedupeKey: `score:${site.id}`,
        metadata: { before, after: scan.securityScore, scanRunId: run.id }
      });
      if (result.created) alerts++;
    }
  }
  return { runId: run.id as string, alerts };
}
