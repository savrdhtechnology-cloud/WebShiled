"use server";

import { redirect } from "next/navigation";
import { clearSession, createDemoSession } from "@/lib/auth";
import { createClient } from "@/lib/supabase/server";

export type AuthState = { error?: string; message?: string };

const DEMO_PASSWORD = "WebShield123!";
const DEMO_ADMIN_EMAIL = "admin@webshield.demo";
const DEMO_CLIENT_EMAIL = "client@webshield.demo";
const PRODUCTION_APP_URL = "https://webshield-savrdh-technology.vercel.app";

function text(formData: FormData, key: string) {
  return String(formData.get(key) || "").trim();
}

export async function loginAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const password = text(formData, "password");
  const next = text(formData, "next") || "/app/dashboard";
  if (!email || password.length < 8) redirect("/login?error=invalid");

  if (process.env.WEB_SHIELD_DEMO_MODE !== "false" && password === DEMO_PASSWORD) {
    if (email === DEMO_ADMIN_EMAIL) {
      await createDemoSession("ADMIN");
      redirect("/admin/dashboard");
    }
    if (email === DEMO_CLIENT_EMAIL) {
      await createDemoSession("OWNER");
      redirect("/app/dashboard");
    }
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) redirect("/login?error=credentials");
  redirect(next.startsWith("/") ? next : "/app/dashboard");
}

export async function registerAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const password = text(formData, "password");
  const name = text(formData, "name");
  if (!name || !email || password.length < 10) redirect("/register?error=invalid");

  const supabase = await createClient();
  const base = (process.env.NEXT_PUBLIC_APP_URL || PRODUCTION_APP_URL).replace(/\/$/, "");
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { display_name: name },
      emailRedirectTo: `${base}/login?message=email-verified`
    }
  });

  if (error || !data.user) redirect("/register?error=signup");
  redirect("/login?message=verify-email");
}

export async function forgotPasswordAction(formData: FormData) {
  const email = text(formData, "email").toLowerCase();
  const supabase = await createClient();
  const base = process.env.NEXT_PUBLIC_APP_URL || PRODUCTION_APP_URL;
  await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${base.replace(/\/$/, "")}/reset-password` });
  redirect("/forgot-password?message=sent");
}

export async function resetPasswordAction(formData: FormData) {
  const password = text(formData, "password");
  if (password.length < 10) redirect("/reset-password?error=weak");
  const supabase = await createClient();
  const { error } = await supabase.auth.updateUser({ password });
  redirect(error ? "/reset-password?error=failed" : "/login?message=password-updated");
}

export async function logoutAction() {
  await clearSession();
  redirect("/");
}
