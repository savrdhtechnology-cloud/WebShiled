import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";
import { runPassiveScan } from "@/lib/passive-scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const reply = (value: unknown, status = 200) =>
  NextResponse.json(value, { status, headers: { "cache-control": "no-store" } });

export async function POST(request: NextRequest) {
  const user = await getCurrentUser();
  if (!user) return reply({ ok: false, error: "Authentication required." }, 401);
  if (user.demo || !user.organizationId || user.organizationId === "unassigned")
    return reply({ ok: false, error: "An assigned real workspace is required." }, 403);
  if (!["OWNER", "ADMIN", "SECURITY_ANALYST"].includes(user.role))
    return reply({ ok: false, error: "Security analyst permissions required." }, 403);

  try {
    const body = await request.json();
    const input = String(body?.url || "").trim();
    const url = new URL(/^https?:\/\//i.test(input) ? input : "https://" + input);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP(S) websites are allowed.");
    const host = url.hostname.toLowerCase().replace(/^www\./, "");
    const client = await createClient();
    // Client account scans must be limited to a registered, verified domain.
    const { data: site, error: siteError } = await client.from("websites")
      .select("id,domain,verified_at,status")
      .eq("organization_id", user.organizationId)
      .eq("domain", host).maybeSingle();
    if (siteError) throw siteError;
    if (!site || !site.verified_at)
      return reply({ ok: false, error: "Add and verify ownership of this domain before running workspace scans." }, 403);

    const started = new Date().toISOString();
    const scan = await runPassiveScan(url.toString());
    // Reports are scoped to the organization and stored using existing RLS-protected schema.
    const { data: saved, error: saveError } = await client.from("security_scan_runs").insert({
      organization_id: user.organizationId, website_id: site.id, status: "COMPLETED",
      security_score: scan.securityScore, security_grade: scan.grade,
      overall_risk: scan.overallRisk, finding_counts: scan.findingCounts,
      findings: scan.findings, scan_payload: scan, started_at: started, completed_at: scan.scannedAt
    }).select("id").single();
    if (saveError) throw saveError;
    const { error: updateError } = await client.from("websites").update({
      security_score: scan.securityScore, security_grade: scan.grade,
      overall_risk: scan.overallRisk, last_scan_at: scan.scannedAt, last_scan: scan
    }).eq("organization_id", user.organizationId).eq("id", site.id);
    if (updateError) throw updateError;
    return reply({ ok: true, scan, scanId: saved.id, saved: true });
  } catch (error) {
    return reply({ ok: false, error: error instanceof Error ? error.message : "Scan failed." }, 400);
  }
}

export async function GET(request: NextRequest) {
  const user = await getCurrentUser();
  if (!user || user.demo || !user.organizationId || user.organizationId === "unassigned")
    return reply({ ok: false, error: "Authentication required." }, 401);
  const client = await createClient();
  const siteId = request.nextUrl.searchParams.get("websiteId");
  let query = client.from("security_scan_runs")
    .select("id,website_id,status,security_score,security_grade,overall_risk,finding_counts,started_at,completed_at,created_at")
    .eq("organization_id", user.organizationId).order("created_at", { ascending: false }).limit(40);
  if (siteId) query = query.eq("website_id", siteId);
  const { data, error } = await query;
  if (error) return reply({ ok: false, error: error.message }, 500);
  return reply({ ok: true, scans: data || [] });
}
