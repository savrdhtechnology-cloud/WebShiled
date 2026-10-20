import { list, put } from "@vercel/blob";
import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth";

const SCOPES = new Set(["landing", "admin"]);
const defaults = {
  accent: "#00d5ff", background: "aurora", motion: true, speed: 50, intensity: 55,
  glow: 50, hover: "lift", click: "ripple", glass: 75, radius: 12, density: "comfortable"
};

function clean(value: unknown) {
  const input = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const result = { ...defaults };
  if (typeof input.accent === "string" && /^#[0-9a-f]{6}$/i.test(input.accent)) result.accent = input.accent;
  if (["aurora","grid","particles","none"].includes(String(input.background))) result.background = String(input.background);
  if (typeof input.motion === "boolean") result.motion = input.motion;
  if (["lift","tilt","none"].includes(String(input.hover))) result.hover = String(input.hover);
  if (["ripple","pulse","none"].includes(String(input.click))) result.click = String(input.click);
  if (["comfortable","compact"].includes(String(input.density))) result.density = String(input.density);
  for (const name of ["speed","intensity","glow","glass","radius"] as const) {
    const v = input[name];
    if (typeof v === "number" && Number.isFinite(v)) {
      (result as Record<string, unknown>)[name] = Math.max(0, Math.min(name === "radius" ? 28 : 100, v));
    }
  }
  return result;
}

async function readScope(scope: string) {
  const prefix = `webshield/appearance/${scope}.json`;
  const found = await list({ prefix, limit: 1 });
  const blob = found.blobs.find(item => item.pathname === prefix);
  if (!blob) return defaults;
  const response = await fetch(blob.url + "?v=" + Date.now(), { cache: "no-store" });
  if (!response.ok) return defaults;
  return clean(await response.json().catch(() => defaults));
}

export async function GET(request: NextRequest) {
  const scope = request.nextUrl.searchParams.get("scope") || "landing";
  if (!SCOPES.has(scope)) return NextResponse.json({ ok: false, error: { message: "Invalid appearance scope." } }, { status: 400 });
  try {
    return NextResponse.json({ ok: true, data: await readScope(scope) }, { headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ ok: true, data: defaults }, { headers: { "cache-control": "no-store" } });
  }
}

export async function POST(request: NextRequest) {
  await requireAdmin();
  const body = await request.json().catch(() => null) as { scope?: string; settings?: unknown } | null;
  const scope = body?.scope || "";
  if (!SCOPES.has(scope)) return NextResponse.json({ ok: false, error: { message: "Invalid appearance scope." } }, { status: 400 });
  const settings = clean(body?.settings);
  await put(`webshield/appearance/${scope}.json`, JSON.stringify(settings), {
    access: "public",
    allowOverwrite: true,
    addRandomSuffix: false,
    contentType: "application/json"
  });
  return NextResponse.json({ ok: true, data: settings }, { headers: { "cache-control": "no-store" } });
}
