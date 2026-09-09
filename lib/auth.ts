import "server-only";

import crypto from "node:crypto";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { AppUser, Role } from "@/lib/types";
import { createClient } from "@/lib/supabase/server";

const DEMO_COOKIE = "ws_demo_session";
const demoMode = process.env.WEB_SHIELD_DEMO_MODE !== "false";

function signingKey() {
  return process.env.AUTH_SECRET || "webshield-demo-only-non-production-key";
}

function sign(payload: string) {
  return crypto.createHmac("sha256", signingKey()).update(payload).digest("base64url");
}

export async function createDemoSession(role: Role = "OWNER") {
  if (!demoMode) throw new Error("Demo authentication is disabled.");
  const user: AppUser = {
    id: `demo-${role.toLowerCase()}`,
    email: role === "ADMIN" ? "admin@demo.webshield.local" : "owner@demo.webshield.local",
    name: role === "ADMIN" ? "WebShield Admin" : "Demo Owner",
    role,
    organizationId: "demo-org",
    demo: true
  };
  const payload = Buffer.from(JSON.stringify({ ...user, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString("base64url");
  const value = `${payload}.${sign(payload)}`;
  const store = await cookies();
  store.set(DEMO_COOKIE, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 8 * 60 * 60
  });
  return user;
}

function parseDemo(value?: string): AppUser | null {
  if (!value || !demoMode) return null;
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return null;
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof parsed.exp !== "number" || parsed.exp < Date.now()) return null;
    return {
      id: parsed.id,
      email: parsed.email,
      name: parsed.name,
      role: parsed.role,
      organizationId: parsed.organizationId,
      demo: true
    };
  } catch {
    return null;
  }
}

export async function getCurrentUser(): Promise<AppUser | null> {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (!error && data?.claims?.sub) {
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

  const store = await cookies();
  return parseDemo(store.get(DEMO_COOKIE)?.value);
}

export async function requireUser() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/app/dashboard");
  return user;
}

export async function requireAdmin() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/admin/dashboard");
  if (!(["OWNER", "ADMIN"] as Role[]).includes(user.role)) redirect("/app/dashboard?denied=admin");
  return user;
}

export async function clearSession() {
  const store = await cookies();
  store.delete(DEMO_COOKIE);
  const supabase = await createClient();
  await supabase.auth.signOut();
}
