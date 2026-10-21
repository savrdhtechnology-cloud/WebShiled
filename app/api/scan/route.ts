import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { runPassiveScan } from "@/lib/passive-scanner";
import { createClient } from "@/lib/supabase/server";
import { persistWebsiteScan } from "@/lib/monitoring/website-scans";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

function host(value: string) {
  try { return new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return ""; }
}

export async function POST(request: NextRequest) {
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ ok: false, error: "Authentication required." }, { status: 401 });

  try {
    const body = await request.json();
    const scan = await runPassiveScan(body?.url);
    let saved: { runId: string; alerts: number; websiteId: string } | null = null;

    // Persist the result when the scanned host belongs to a website in this workspace.
    if (user.organizationId && user.organizationId !== "unassigned" && ["OWNER", "ADMIN", "SECURITY_ANALYST"].includes(user.role)) {
      const client = await createClient();
      let query = client.from("websites")
        .select("id,organization_id,domain,security_score,last_scan,monitoring_interval_minutes")
        .eq("organization_id", user.organizationId);
      query = body?.websiteId ? query.eq("id", String(body.websiteId)) : query.in("domain", [host(scan.hostname), host(String(body?.url || ""))].filter(Boolean));
      const { data: site } = await query.limit(1).maybeSingle();
      if (site) {
        const result = await persistWebsiteScan(client, site, scan);
        saved = { ...result, websiteId: site.id };
      }
    }
    return NextResponse.json({ ok: true, scan, saved }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";
    return NextResponse.json({ ok: false, error: message }, { status: 400 });
  }
}
