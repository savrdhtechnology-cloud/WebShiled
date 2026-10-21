import "server-only";

import { createHmac } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { adminConfigured, createAdminClient } from "@/lib/supabase/admin";
import { publicAddresses } from "@/lib/passive-scanner";

export type Db = SupabaseClient<any, any, any>;
export type AlertSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

const ORDER: AlertSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export function normalizeSeverity(value: string): AlertSeverity {
  const v = String(value || "").toUpperCase();
  if (v === "INFO") return "LOW";
  return (ORDER as string[]).includes(v) ? v as AlertSeverity : "MEDIUM";
}
function atLeast(value: AlertSeverity, threshold: AlertSeverity) {
  return ORDER.indexOf(value) >= ORDER.indexOf(threshold);
}

export type AlertInput = {
  organizationId: string;
  websiteId?: string | null;
  connectionId?: string | null;
  type: string;
  severity: string;
  title: string;
  message: string;
  source: "uptime" | "ssl" | "scan" | "database_audit" | "data_guard" | "traffic" | "system";
  dedupeKey: string;
  metadata?: Record<string, unknown>;
};

export type AlertResult = { id: string | null; created: boolean; notified: number };

/**
 * Creates an alert, or bumps the occurrence count of the matching open alert.
 * Notifications (email / webhook) are only sent when a NEW alert is created,
 * so a website that stays down does not flood the inbox.
 */
export async function raiseAlert(db: Db, input: AlertInput): Promise<AlertResult> {
  const severity = normalizeSeverity(input.severity);
  const now = new Date().toISOString();
  const { data: existing } = await db.from("alerts")
    .select("id,severity,occurrences")
    .eq("organization_id", input.organizationId)
    .eq("dedupe_key", input.dedupeKey)
    .is("acknowledged_at", null)
    .maybeSingle();

  if (existing) {
    const higher = atLeast(severity, normalizeSeverity(existing.severity)) ? severity : existing.severity;
    await db.from("alerts").update({
      occurrences: Number(existing.occurrences || 1) + 1,
      last_seen_at: now,
      severity: higher,
      message: input.message.slice(0, 2000),
      metadata: input.metadata || {}
    }).eq("organization_id", input.organizationId).eq("id", existing.id);
    return { id: existing.id, created: false, notified: 0 };
  }

  const { data, error } = await db.from("alerts").insert({
    organization_id: input.organizationId,
    website_id: input.websiteId || null,
    connection_id: input.connectionId || null,
    type: input.type,
    severity,
    title: input.title.slice(0, 300),
    message: input.message.slice(0, 2000),
    source: input.source,
    dedupe_key: input.dedupeKey,
    metadata: input.metadata || {},
    last_seen_at: now
  }).select("id").single();

  if (error) {
    // 23505: another worker created the same open alert concurrently.
    if ((error as { code?: string }).code === "23505") return { id: null, created: false, notified: 0 };
    throw error;
  }
  const notified = await notify(db, { ...input, severity }, data.id).catch(() => 0);
  return { id: data.id, created: true, notified };
}

/** Marks open alerts with this dedupe key as resolved (e.g. website back up). */
export async function resolveAlert(db: Db, organizationId: string, dedupeKey: string, note: string) {
  const { data } = await db.from("alerts")
    .select("id,metadata")
    .eq("organization_id", organizationId)
    .eq("dedupe_key", dedupeKey)
    .is("acknowledged_at", null)
    .maybeSingle();
  if (!data) return false;
  await db.from("alerts").update({
    acknowledged_at: new Date().toISOString(),
    metadata: { ...(data.metadata || {}), autoResolved: true, resolution: note }
  }).eq("id", data.id).eq("organization_id", organizationId);
  return true;
}

type Channels = { enabled: boolean; email_recipients: string[]; webhook_url: string | null; min_severity: AlertSeverity };

async function channelsFor(db: Db, organizationId: string): Promise<Channels> {
  const { data } = await db.from("alert_channels")
    .select("enabled,email_recipients,webhook_url,min_severity")
    .eq("organization_id", organizationId)
    .maybeSingle();
  if (data) return { ...data, min_severity: normalizeSeverity(data.min_severity) } as Channels;
  // No explicit settings: email workspace owners/admins about HIGH and CRITICAL alerts.
  return { enabled: true, email_recipients: await ownerEmails(organizationId), webhook_url: null, min_severity: "HIGH" };
}

async function ownerEmails(organizationId: string) {
  if (!adminConfigured()) return [];
  try {
    const admin = createAdminClient();
    const { data } = await admin.from("team_members").select("user_id").eq("organization_id", organizationId).in("role", ["OWNER", "ADMIN"]).limit(10);
    const emails: string[] = [];
    for (const row of data || []) {
      const { data: user } = await admin.auth.admin.getUserById(row.user_id);
      if (user?.user?.email) emails.push(user.user.email);
    }
    return emails;
  } catch {
    return [];
  }
}

async function record(organizationId: string, alertId: string, channel: "EMAIL" | "WEBHOOK", recipient: string, ok: boolean, error?: string) {
  if (!adminConfigured()) return;
  await createAdminClient().from("notifications").insert({
    organization_id: organizationId,
    alert_id: alertId,
    channel,
    recipient: recipient.slice(0, 300),
    status: ok ? "SENT" : "FAILED",
    sent_at: ok ? new Date().toISOString() : null,
    error: error ? error.slice(0, 500) : null
  });
}

function appUrl() {
  return (process.env.NEXT_PUBLIC_APP_URL || "https://savrdhtechnologies.com/webshield").replace(/\/$/, "");
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

async function sendEmail(to: string[], input: AlertInput & { severity: AlertSeverity }) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.ALERT_EMAIL_FROM;
  if (!key || !from) throw new Error("Email delivery is not configured (RESEND_API_KEY / ALERT_EMAIL_FROM).");
  const link = `${appUrl()}/app/alerts`;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({
      from,
      to,
      subject: `[WebShield ${input.severity}] ${input.title}`.slice(0, 200),
      text: `${input.title}\n\n${input.message}\n\nSeverity: ${input.severity}\nSource: ${input.source}\n\nOpen WebShield: ${link}`,
      html: `<div style="font-family:system-ui,sans-serif;max-width:560px"><p style="font-size:12px;letter-spacing:.08em;color:#64748b">WEBSHIELD SECURITY ALERT · ${input.severity}</p><h2 style="margin:0 0 12px">${escapeHtml(input.title)}</h2><p>${escapeHtml(input.message)}</p><p style="color:#64748b">Source: ${escapeHtml(input.source)}</p><p><a href="${link}">Open alerts in WebShield →</a></p></div>`
    }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Email provider returned ${response.status}.`);
}

async function sendWebhook(url: string, payload: Record<string, unknown>) {
  const target = new URL(url);
  if (target.protocol !== "https:") throw new Error("Webhook must use HTTPS.");
  await publicAddresses(target.hostname);
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { "content-type": "application/json", "user-agent": "WebShield-Alerts/1.0" };
  if (process.env.WEBHOOK_SECRET) headers["x-webshield-signature"] = "sha256=" + createHmac("sha256", process.env.WEBHOOK_SECRET).update(body).digest("hex");
  const response = await fetch(target, { method: "POST", headers, body, redirect: "manual", signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`Webhook returned ${response.status}.`);
}

async function notify(db: Db, input: AlertInput & { severity: AlertSeverity }, alertId: string) {
  const channels = await channelsFor(db, input.organizationId);
  if (!channels.enabled || !atLeast(input.severity, channels.min_severity)) return 0;
  let sent = 0;
  const recipients = (channels.email_recipients || []).filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)).slice(0, 10);
  if (recipients.length) {
    try { await sendEmail(recipients, input); sent++; await record(input.organizationId, alertId, "EMAIL", recipients.join(","), true); }
    catch (error) { await record(input.organizationId, alertId, "EMAIL", recipients.join(","), false, error instanceof Error ? error.message : "Email failed"); }
  }
  if (channels.webhook_url) {
    try {
      await sendWebhook(channels.webhook_url, {
        event: "webshield.alert",
        alertId,
        organizationId: input.organizationId,
        severity: input.severity,
        type: input.type,
        source: input.source,
        title: input.title,
        message: input.message,
        websiteId: input.websiteId || null,
        connectionId: input.connectionId || null,
        metadata: input.metadata || {},
        createdAt: new Date().toISOString()
      });
      sent++;
      await record(input.organizationId, alertId, "WEBHOOK", channels.webhook_url, true);
    } catch (error) {
      await record(input.organizationId, alertId, "WEBHOOK", channels.webhook_url, false, error instanceof Error ? error.message : "Webhook failed");
    }
  }
  return sent;
}
