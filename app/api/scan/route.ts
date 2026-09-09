import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { runPassiveScan } from "@/lib/passive-scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ ok: false, error: "Authentication required." }, { status: 401 });

  try {
    const body = await request.json();
    const scan = await runPassiveScan(body?.url);
    return NextResponse.json({ ok: true, scan }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";
    return NextResponse.json({ ok: false, error: message }, { status: 400 });
  }
}
