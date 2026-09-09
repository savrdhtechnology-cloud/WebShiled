"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { WebsiteScanner } from "@/components/website-scanner";

type DashboardData = {
  metrics?: { websites:number; visitors:number; activeVisitors:number; threats:number; blockedRequests:number; openAlerts:number };
  threats?: Array<Record<string, any>>;
  alerts?: Array<Record<string, any>>;
  organizationId?: string;
  websites?: number;
  threatsCount?: number;
  openAlerts?: number;
  openTickets?: number;
};

function Notice({ message }: { message: string }) {
  return <article className="panel"><div className="panelHead"><div><h3>Backend status</h3><p>{message}</p></div><span className="statusTag medium">ACTION REQUIRED</span></div><div className="buttonRow"><Link href="/register" className="btn small">Create real account</Link><Link href="/app/websites" className="ghostBtn small">Open Website Scan</Link></div></article>;
}

export function BackendDashboard({ admin = false }: { admin?: boolean }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(admin ? "/api/admin" : "/api/dashboard", { cache: "no-store" })
      .then(async r => {
        const body = await r.json();
        if (!r.ok || !body.ok) throw new Error(body?.error?.message || "Backend data unavailable.");
        return body.data;
      })
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : "Backend data unavailable."))
      .finally(() => setLoading(false));
  }, [admin]);

  if (admin) {
    const stats = data ? [
      ["Websites", String(data.websites ?? 0), "Database records", "globe"],
      ["Threat Events", String(data.threats ?? 0), "Database records", "threat"],
      ["Open Alerts", String(data.openAlerts ?? 0), "Needs review", "bell"],
      ["Open Tickets", String(data.openTickets ?? 0), "Support queue", "visitors"]
    ] : [];
    return <div className="pageWrap">
      <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Administration</div><h1>Admin Dashboard</h1><p>Scan websites and manage real WebShield backend records from one control center.</p></div><span className="statusTag safe">SUPABASE BACKEND</span></div>
      <WebsiteScanner />
      {loading && <article className="panel"><p>Loading backend data…</p></article>}
      {error && <Notice message={error}/>} 
      {data && <>
        <div className="metricGrid compact">{stats.map(([label,value,note,icon])=><article className="metricCard" key={label}><div className="metricTop"><span>{label}</span><div className="metricIcon"><Icon name={icon}/></div></div><strong>{value}</strong><small>{note}</small></article>)}</div>
        <article className="panel" style={{marginTop:16}}><div className="panelHead"><div><h3>Essential administration</h3><p>Only high-value platform modules are kept in the sidebar.</p></div></div><div className="endpointGrid"><Link href="/admin/clients">Clients</Link><Link href="/admin/websites">Websites</Link><Link href="/admin/security-events">Security Events</Link><Link href="/admin/plans">Plans & Billing</Link><Link href="/admin/support-tickets">Support</Link><Link href="/admin/system-settings">Settings</Link></div></article>
      </>}
    </div>;
  }

  const m = data?.metrics;
  return <div className="pageWrap">
    <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Overview</div><h1>Security Dashboard</h1><p>Real WebShield database metrics. No simulated traffic totals are shown here.</p></div><span className="statusTag safe">BACKEND DATA</span></div>
    {loading && <article className="panel"><p>Loading backend data…</p></article>}
    {error && <Notice message={error}/>} 
    {m && <>
      <div className="metricGrid">{[
        ["Websites",m.websites,"Connected inventory","globe"],
        ["Total Visitors",m.visitors,"Stored visitor records","visitors"],
        ["Active Visitors",m.activeVisitors,"Seen in last 5 minutes","visitors"],
        ["Threat Events",m.threats,"Stored detections","threat"],
        ["Blocked Requests",m.blockedRequests,"Blocked sessions","firewall"],
        ["Open Alerts",m.openAlerts,"Unacknowledged","bell"]
      ].map(([label,value,note,icon])=><article className="metricCard" key={String(label)}><div className="metricTop"><span>{label}</span><div className="metricIcon"><Icon name={String(icon)}/></div></div><strong>{value}</strong><small>{note}</small></article>)}</div>
      <div className="dashboardGrid equal">
        <article className="panel"><div className="panelHead"><div><h3>Recent Threats</h3><p>Latest threat_events records.</p></div><Link href="/app/threat-center" className="textButton">View all →</Link></div>{(data?.threats || []).length ? (data?.threats || []).map(t=><div className="eventRow" key={t.id}><span className={`alertIcon ${(t.severity || "low").toLowerCase()}`}><Icon name="threat"/></span><div><b>{t.type}</b><small>{t.source_ip || "Unknown IP"} · {t.target_url || "—"}</small></div><span className="riskScore">{t.risk_score}</span></div>) : <p>No threat events recorded yet.</p>}</article>
        <article className="panel"><div className="panelHead"><div><h3>Recent Alerts</h3><p>Latest alerts records.</p></div><Link href="/app/alerts" className="textButton">View all →</Link></div>{(data?.alerts || []).length ? (data?.alerts || []).map(a=><div className="eventRow" key={a.id}><span className={`alertIcon ${(a.severity || "low").toLowerCase()}`}><Icon name="bell"/></span><div><b>{a.title}</b><small>{a.message || a.type}</small></div><span>{a.acknowledged_at ? "ACK" : "OPEN"}</span></div>) : <p>No alerts recorded yet.</p>}</article>
      </div>
    </>}
  </div>;
}
