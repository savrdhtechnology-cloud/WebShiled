import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";
import { runMonitoringCycle } from "@/lib/monitoring/runner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

// "Run checks now" from the dashboard. Runs with the signed-in user's session,
// so Row Level Security keeps the run inside that user's workspace.
export async function POST(request: NextRequest) {
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ ok: false, error: { message: "Authentication required." } }, { status: 401 });
  if (!user.organizationId || user.organizationId === "unassigned") return NextResponse.json({ ok: false, error: { message: "No workspace assigned." } }, { status: 409 });
  if (!["OWNER", "ADMIN", "SECURITY_ANALYST"].includes(user.role)) return NextResponse.json({ ok: false, error: { message: "A security role is required to run checks." } }, { status: 403 });

  const body = await request.json().catch(() => ({})) as { websiteId?: string; scope?: string };
  const scope = String(body.scope || "all");
  try {
    const report = await runMonitoringCycle(await createClient(), {
      organizationId: user.organizationId,
      websiteId: body.websiteId ? String(body.websiteId) : undefined,
      force: true,
      budgetMs: 100_000,
      includeWebsites: scope !== "databases",
      includeDatabases: scope !== "websites"
    });
    return NextResponse.json({ ok: true, data: report }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ ok: false, error: { message: error instanceof Error ? error.message : "Checks failed." } }, { status: 500 });
  }
}
