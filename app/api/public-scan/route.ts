import { NextRequest, NextResponse } from "next/server";
import { runPassiveScan } from "@/lib/passive-scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const buckets = new Map<string, { count: number; resetAt: number }>();
function rateLimit(key: string) {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || existing.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + 10 * 60_000 });
    return false;
  }
  existing.count += 1;
  return existing.count > 10;
}

export async function POST(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (rateLimit(ip)) return NextResponse.json({ ok: false, error: "Scan limit reached. Try again later." }, { status: 429 });

  try {
    const body = await request.json();
    const scan = await runPassiveScan(body?.url);
    return NextResponse.json({ ok: true, scan }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ ok: false, error: error instanceof Error ? error.message : "Scan failed." }, { status: 400 });
  }
}
