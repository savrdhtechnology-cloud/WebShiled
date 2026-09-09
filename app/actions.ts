"use server";

import { redirect } from "next/navigation";
import { clearSession, createDemoSession } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";
import type { Role } from "@/lib/types";

export type AuthState = { error?: string; message?: string };

function text(formData: FormData, key: string) {
  return String(formData.get(key) || "").trim();
}

export async function loginAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const password = text(formData, "password");
  const next = text(formData, "next") || "/app/dashboard";
  if (!email || password.length < 8) redirect("/login?error=invalid");

  const supabase = await createClient();
  if (supabase) {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) redirect("/login?error=credentials");
    redirect(next.startsWith("/") ? next : "/app/dashboard");
  }

  if (process.env.WEB_SHIELD_DEMO_MODE !== "false") {
    const role: Role = email.startsWith("admin@") ? "ADMIN" : "OWNER";
    await createDemoSession(role);
    redirect(role === "ADMIN" && next.startsWith("/admin") ? next : "/app/dashboard");
  }
  redirect("/login?error=not-configured");
}

export async function registerAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const password = text(formData, "password");
  const name = text(formData, "name");
  if (!name || !email || password.length < 10) redirect("/register?error=invalid");
  const supabase = await createClient();
  if (!supabase) redirect("/register?error=not-configured");
  const { error } = await supabase.auth.signUp({ email, password, options: { data: { display_name: name } } });
  if (error) redirect("/register?error=signup");
  redirect("/login?message=verify-email");
}

export async function forgotPasswordAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const supabase = await createClient();
  if (!supabase) redirect("/forgot-password?message=integration-ready");
  const base = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
  await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${base}/reset-password` });
  redirect("/forgot-password?message=sent");
}

export async function resetPasswordAction(formData: FormData) {
  const password = text(formData, "password");
  if (password.length < 10) redirect("/reset-password?error=weak");
  const supabase = await createClient();
  if (!supabase) redirect("/reset-password?error=not-configured");
  const { error } = await supabase.auth.updateUser({ password });
  redirect(error ? "/reset-password?error=failed" : "/login?message=password-updated");
}

export async function logoutAction() {
  await clearSession();
  redirect("/");
}
