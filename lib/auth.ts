import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { AppUser, Role } from "@/lib/types";
import { createClient } from "@/lib/supabase/server";

export async function createDemoSession(_role?: Role): Promise<never> {
  throw new Error("Demo authentication is disabled.");
}

export async function getCurrentUser(): Promise<AppUser | null> {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error || !data?.claims?.sub) return null;

  const claims = data.claims as Record<string, unknown>;
  const id = String(claims.sub);
  const email = String(claims.email || "");

  const [{ data: membership }, { data: profile }] = await Promise.all([
    supabase.from("team_members").select("organization_id,role").eq("user_id", id).limit(1).maybeSingle(),
    supabase.from("users").select("full_name").eq("id", id).maybeSingle()
  ]);

  return {
    id,
    email,
    name: String(profile?.full_name || email || "WebShield User"),
    role: String(membership?.role || "VIEWER") as Role,
    organizationId: String(membership?.organization_id || "unassigned"),
    demo: false
  };
}

export async function requireUser() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/app/dashboard");
  if (!user.organizationId || user.organizationId === "unassigned") redirect("/login?error=no-workspace");
  return user;
}

export async function requireAdmin() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/admin/dashboard");
  if (!user.organizationId || user.organizationId === "unassigned") redirect("/login?error=no-workspace");
  if (!(["OWNER", "ADMIN"] as Role[]).includes(user.role)) redirect("/app/dashboard?denied=admin");
  return user;
}

export async function clearSession() {
  const store = await cookies();
  store.delete("ws_demo_session");
  const supabase = await createClient();
  await supabase.auth.signOut();
}
