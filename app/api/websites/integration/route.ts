import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

function out(data: unknown, status = 200) {
  return NextResponse.json({ ok: status < 400, data: status < 400 ? data : null, error: status >= 400 ? data : null }, { status });
}

async function siteForUser(id: string) {
  const user = await getCurrentUser();
  if (!user) return { error: out({ message: "Authentication required." }, 401) };
  if (user.demo) return { error: out({ message: "Use a real account to connect websites." }, 409) };
  if (!user.organizationId || user.organizationId === "unassigned") return { error: out({ message: "No workspace assigned." }, 409) };

  const client = await createClient();
  const { data, error } = await client
    .from("websites")
    .select("id,domain,status,verified_at,integration_status,collector_key,collector_enabled,last_event_at")
    .eq("organization_id", user.organizationId)
    .eq("id", id)
    .maybeSingle();
  if (error) return { error: out({ message: error.message }, 500) };
  if (!data) return { error: out({ message: "Website not found." }, 404) };
  return { user, client, site: data };
}

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id") || "";
  if (!id) return out({ message: "Website id is required." }, 400);
  const resolved = await siteForUser(id);
  if (resolved.error) return resolved.error;
  return out(resolved.site);
}

export async function POST(request: NextRequest) {
  if (!request.headers.get("content-type")?.includes("application/json")) return out({ message: "application/json required." }, 415);
  const body = await request.json().catch(() => null) as null | { id?: string; action?: string };
  const id = String(body?.id || "");
  const action = String(body?.action || "enable");
  if (!id) return out({ message: "Website id is required." }, 400);

  const resolved = await siteForUser(id);
  if (resolved.error) return resolved.error;
  const { client, site } = resolved;

  if (action === "enable") {
    const { data, error } = await client
      .from("websites")
      .update({ collector_enabled: true })
      .eq("id", site.id)
      .select("id,domain,status,verified_at,integration_status,collector_key,collector_enabled,last_event_at")
      .single();
    if (error) return out({ message: error.message }, 500);
    return out(data);
  }

  if (action === "disable") {
    const { data, error } = await client
      .from("websites")
      .update({ collector_enabled: false, integration_status: "NOT_CONNECTED" })
      .eq("id", site.id)
      .select("id,domain,status,verified_at,integration_status,collector_key,collector_enabled,last_event_at")
      .single();
    if (error) return out({ message: error.message }, 500);
    return out(data);
  }

  if (action === "verify") {
    const { data: fresh, error: freshError } = await client
      .from("websites")
      .select("id,domain,status,verified_at,integration_status,collector_key,collector_enabled,last_event_at")
      .eq("id", site.id)
      .single();
    if (freshError) return out({ message: freshError.message }, 500);
    if (!fresh.last_event_at) return out({ message: "No collector event received yet. Install the snippet and open the website once, then try again." }, 409);

    const { data, error } = await client
      .from("websites")
      .update({ verified_at: fresh.verified_at || new Date().toISOString(), status: "CONNECTED", integration_status: "COLLECTOR_CONNECTED" })
      .eq("id", site.id)
      .select("id,domain,status,verified_at,integration_status,collector_key,collector_enabled,last_event_at")
      .single();
    if (error) return out({ message: error.message }, 500);
    return out(data);
  }

  return out({ message: "Unsupported integration action." }, 400);
}
