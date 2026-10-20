const API = "https://api.supabase.com";

export function validateProjectRef(value: string) {
  const ref = value.trim().toLowerCase();
  if (!/^[a-z0-9]{10,40}$/.test(ref)) throw new Error("Enter a valid Supabase project ref.");
  return ref;
}

async function request(path: string, token: string, init: RequestInit = {}) {
  const response = await fetch(API + path, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...(init.headers || {})
    },
    cache: "no-store",
    signal: AbortSignal.timeout(12000)
  });
  const text = await response.text();
  let data: unknown = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const message = typeof data === "object" && data && "message" in data
      ? String((data as { message?: unknown }).message || "Supabase Management API request failed.")
      : `Supabase Management API returned ${response.status}.`;
    const error = new Error(message) as Error & { status?: number };
    error.status = response.status;
    throw error;
  }
  return data;
}

function rows(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) return value.filter(x => x && typeof x === "object") as Array<Record<string, unknown>>;
  if (value && typeof value === "object") {
    for (const key of ["result", "data", "rows"]) {
      const candidate = (value as Record<string, unknown>)[key];
      if (Array.isArray(candidate)) return candidate.filter(x => x && typeof x === "object") as Array<Record<string, unknown>>;
    }
  }
  return [];
}

export async function runReadOnlyQuery(projectRef: string, token: string, query: string) {
  const data = await request(`/v1/projects/${validateProjectRef(projectRef)}/database/query/read-only`, token, {
    method: "POST",
    body: JSON.stringify({ query })
  });
  return rows(data);
}

export async function runWriteQuery(projectRef: string, token: string, query: string) {
  return request(`/v1/projects/${validateProjectRef(projectRef)}/database/query`, token, {
    method: "POST",
    body: JSON.stringify({ query, read_only: false })
  });
}

export async function verifySupabaseDatabaseAccess(projectRef: string, token: string) {
  const result = await runReadOnlyQuery(projectRef, token, "select current_database() as database_name, current_user as database_user");
  if (!result.length) throw new Error("Supabase database access could not be verified.");
  return result[0];
}

export async function getSupabaseProjectConfig(projectRef: string, token: string) {
  try {
    return await request(`/v2/projects/${validateProjectRef(projectRef)}/config`, token, { method: "GET" });
  } catch {
    return null;
  }
}
