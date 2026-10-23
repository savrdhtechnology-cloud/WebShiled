import "server-only";

// WebShield is not self-serve. A customer asks for a free trial on the landing page (a lead is created in the
// Savrdh Sales CRM), staff create a trial link for that lead, and only that link lets the customer register.
// The link's token is checked against the same service that issued it.
const DEMO_API = "https://ldffgetuzoeupuhoaubn.supabase.co/functions/v1/savrdh-demo-access";
export const TRIAL_PRODUCT = "webshield";

export async function verifyTrialToken(token: string | null | undefined): Promise<boolean> {
  const value = String(token || "").trim();
  if (!/^[0-9a-f]{64}$/i.test(value)) return false;
  try {
    const res = await fetch(DEMO_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "verify_demo", token: value }),
      cache: "no-store",
      signal: AbortSignal.timeout(8000)
    });
    const data = await res.json().catch(() => ({}));
    return res.ok && data?.valid === true && data?.productSlug === TRIAL_PRODUCT;
  } catch {
    return false;
  }
}
