const EXPECTED_PROJECT_REF = "ldffgetuzoeupuhoaubn";
const FALLBACK_URL = `https://${EXPECTED_PROJECT_REF}.supabase.co`;
const FALLBACK_PUBLISHABLE_KEY = "sb_publishable_KzdI4K0qLXgi3MhA5GXPhg_6f5vB8By";

const envUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const envKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || "";

// WebShield authentication and telemetry must use the same Supabase project.
// Ignore stale/mismatched deployment environment variables from older Savrdh apps.
export const SUPABASE_URL = envUrl.includes(EXPECTED_PROJECT_REF) ? envUrl : FALLBACK_URL;
export const SUPABASE_PUBLISHABLE_KEY = envUrl.includes(EXPECTED_PROJECT_REF) && envKey
  ? envKey
  : FALLBACK_PUBLISHABLE_KEY;
