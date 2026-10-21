import "server-only";

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { SUPABASE_URL } from "@/lib/supabase/config";

// Privileged server-side client used ONLY by background monitoring (cron),
// the server ingest endpoint and alert delivery. It bypasses RLS, so every
// caller must scope its queries by organization_id itself.
// Configure with the Supabase "secret" API key of the
// WebShield project in the WEBSHIELD_SUPABASE_SECRET_KEY environment variable.

let cached: SupabaseClient | null = null;

export function adminConfigured() {
  return Boolean(process.env.WEBSHIELD_SUPABASE_SECRET_KEY);
}

export function createAdminClient(): SupabaseClient {
  const key = process.env.WEBSHIELD_SUPABASE_SECRET_KEY || "";
  if (!key) throw new Error("WEBSHIELD_SUPABASE_SECRET_KEY is not configured on the server.");
  if (!cached) {
    cached = createClient(SUPABASE_URL, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      global: { headers: { "x-client-info": "webshield-monitor" } }
    });
  }
  return cached;
}
