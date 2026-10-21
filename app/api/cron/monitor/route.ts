import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { adminConfigured, createAdminClient } from "@/lib/supabase/admin";
import { runMonitoringCycle } from "@/lib/monitoring/runner";
import { looksLikeJwt, verifyGithubActionsToken } from "@/lib/monitoring/github-oidc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

function secretMatches(header: string) {
  const secret = process.env.CRON_SECRET || "";
  if (secret.length < 16) return false;
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(header);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Vercel Cron (CRON_SECRET) or the GitHub Actions monitoring workflow (signed OIDC token). */
async function authorized(request: NextRequest) {
  const header = request.headers.get("authorization") || "";
  if (secretMatches(header)) return true;
  const token = header.replace(/^Bearer\s+/i, "");
  if (!looksLikeJwt(token)) return false;
  try { await verifyGithubActionsToken(token); return true; } catch { return false; }
}

// Called by Vercel Cron ("Authorization: Bearer $CRON_SECRET") and by
// .github/workflows/monitor.yml with a GitHub-signed OIDC token.
export async function GET(request: NextRequest) {
  if (!(await authorized(request))) return NextResponse.json({ ok: false, error: "Unauthorized." }, { status: 401 });
  if (!adminConfigured()) return NextResponse.json({ ok: false, error: "WEBSHIELD_SUPABASE_SECRET_KEY is not configured." }, { status: 503 });
  try {
    const report = await runMonitoringCycle(createAdminClient(), { budgetMs: 45_000 });
    return NextResponse.json({
      ok: true,
      summary: {
        websites: report.websites.length,
        databases: report.databases.length,
        alertsCreated: report.alertsCreated,
        skipped: report.skipped,
        errors: [...report.websites, ...report.databases].filter(x => x.error).length
      },
      startedAt: report.startedAt,
      finishedAt: report.finishedAt
    }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ ok: false, error: error instanceof Error ? error.message : "Monitoring cycle failed." }, { status: 500 });
  }
}
