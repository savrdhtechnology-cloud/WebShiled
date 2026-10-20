const EXPECTED_PROJECT_REF = "szvxrgbshmmsvujkusdm";
const FALLBACK_URL = `https://${EXPECTED_PROJECT_REF}.supabase.co`;
const FALLBACK_PUBLISHABLE_KEY = "sb_publishable_uh2lu-H3yp3slYd-M9-5eQ_gBfL6imB";

const envUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const envKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || "";

// WebShield authentication, telemetry and security modules must all use the
// dedicated WebShield Supabase project. Ignore stale deployment variables
// from other Savrdh products.
export const SUPABASE_URL = envUrl.includes(EXPECTED_PROJECT_REF) ? envUrl : FALLBACK_URL;
export const SUPABASE_PUBLISHABLE_KEY = envUrl.includes(EXPECTED_PROJECT_REF) && envKey
  ? envKey
  : FALLBACK_PUBLISHABLE_KEY;
