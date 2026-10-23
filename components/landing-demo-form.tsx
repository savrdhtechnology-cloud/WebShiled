"use client";

import { useState } from "react";

// Same public endpoint every Savrdh product landing page uses. It creates a Hot / New lead in the
// Savrdh Sales CRM (source: Website, product: WebShield) so the sales team follows up.
const DEMO_API = "https://ldffgetuzoeupuhoaubn.supabase.co/functions/v1/savrdh-demo-access";

export function LandingDemoForm() {
  const [form, setForm] = useState({ name: "", company: "", email: "", phone: "", website: "", emailConsent: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [ref, setRef] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(DEMO_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "request_demo_booking",
          productSlug: "webshield",
          name: form.name,
          company: form.company,
          email: form.email,
          phone: form.phone,
          notes: "FREE TRIAL REQUEST (staff: create a WebShield trial link for this lead). " + (form.website ? `Website to protect: ${form.website}` : ""),
          emailConsent: form.emailConsent,
          sourcePage: window.location.href
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) throw new Error(data.error || "Please try again.");
      setRef(String(data.leadRef || ""));
    } catch (e) {
      setError((e instanceof Error ? e.message : "Could not send.") + " You can also call +91 8109995906.");
    } finally {
      setBusy(false);
    }
  }

  if (ref) {
    return (
      <div className="lpDemoDone" role="status">
        <span>REQUEST RECEIVED</span>
        <h3>Thank you, your trial request is in.</h3>
        <p>Our team will review it and email you a personal activation link. Request reference: <b>{ref}</b></p>
      </div>
    );
  }

  const set = (key: "name" | "company" | "email" | "phone" | "website") => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: e.target.value });
  return (
    <form className="lpDemoForm" onSubmit={submit}>
      <h3>Request your free trial</h3>
      <p>Tell us a little about you. We will review your request and email you an activation link.</p>
      <div className="lpFields">
        <label>Full name<input required maxLength={120} autoComplete="name" value={form.name} onChange={set("name")} /></label>
        <label>Company<input maxLength={160} autoComplete="organization" value={form.company} onChange={set("company")} /></label>
        <label>Work email<input required type="email" maxLength={180} autoComplete="email" value={form.email} onChange={set("email")} /></label>
        <label>Mobile number<input required type="tel" maxLength={30} autoComplete="tel" value={form.phone} onChange={set("phone")} /></label>
        <label className="wide">Website to protect (optional)<input maxLength={200} placeholder="https://your-website.com" value={form.website} onChange={set("website")} /></label>
      </div>
      <label className="lpConsent"><input required type="checkbox" checked={form.emailConsent} onChange={(e) => setForm({ ...form, emailConsent: e.target.checked })} /><span>Please contact me about this WebShield trial request.</span></label>
      {error && <p role="alert" className="lpError">{error}</p>}
      <button type="submit" disabled={busy}>{busy ? "Sending…" : "Request my trial"}</button>
    </form>
  );
}
