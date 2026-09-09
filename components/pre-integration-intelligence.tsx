"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Icon } from "@/components/icons";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type Finding = { severity: Severity; category: string; title: string; detail: string; impact: string; fix: string };
type StoredScan = {
  requestedUrl: string;
  finalUrl: string;
  hostname: string;
  status: number;
  statusText?: string;
  responseMs: number;
  https: boolean;
  redirectedToHttps: boolean;
  securityScore: number;
  grade: string;
  overallRisk: Severity;
  findingCounts: Record<Severity, number>;
  findings: Finding[];
  headers: { key: string; label: string; present: boolean; value: string | null }[];
  server: string | null;
  poweredBy: string | null;
  cors: string | null;
  cookies: { observed: number; missingSecure: number; missingHttpOnly: number; missingSameSite: number };
  dns: { resolved: boolean; addresses: { address: string; family: number }[] };
  technologies: { signal: string; value: string }[];
  scannedAt: string;
};

const STORAGE_KEY = "webshield:last-scan";

function useLatestScan() {
  const [scan, setScan] = useState<StoredScan | null>(null);
  useEffect(() => {
    const read = () => {
      try {
        const raw = window.localStorage.getItem(STORAGE_KEY);
        setScan(raw ? JSON.parse(raw) as StoredScan : null);
      } catch { setScan(null); }
    };
    read();
    window.addEventListener("storage", read);
    window.addEventListener("webshield:scan-updated", read as EventListener);
    return () => {
      window.removeEventListener("storage", read);
      window.removeEventListener("webshield:scan-updated", read as EventListener);
    };
  }, []);
  return scan;
}

function tagTone(severity: string) {
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "safe";
}

export function PreIntegrationIntelligence({ compact = false }: { compact?: boolean }) {
  const scan = useLatestScan();
  if (!scan) return <article className="panel" style={{marginTop:16}}><div className="panelHead"><div><h3>Pre-Integration Website Intelligence</h3><p>Run a website scan first. WebShield will place the latest external posture result on this dashboard.</p></div><span className="statusTag medium">NO SCAN YET</span></div><div className="buttonRow"><Link href="/app/websites" className="btn small">Scan a Website</Link></div></article>;

  const present = scan.headers?.filter(h => h.present).length || 0;
  const missing = (scan.headers?.length || 0) - present;

  return <div style={{marginTop: compact ? 0 : 16}}>
    <div className="metricGrid compact">
      <article className="metricCard"><span>Scanned Website</span><strong style={{fontSize:18}}>{scan.hostname}</strong><small>External passive intelligence</small></article>
      <article className="metricCard"><span>Security Score</span><strong>{scan.securityScore}/100</strong><small>Grade {scan.grade}</small></article>
      <article className="metricCard"><span>Overall Risk</span><strong>{scan.overallRisk}</strong><small>{scan.findings?.length || 0} finding(s)</small></article>
      <article className="metricCard"><span>Security Layers</span><strong>{present}/{scan.headers?.length || 0}</strong><small>{missing} missing controls</small></article>
    </div>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Website & Infrastructure</h3><p>Publicly observable endpoint information — these are hosting/CDN IPs, not visitor IPs.</p></div><span className="statusTag safe">LIVE SCAN</span></div>
        <div className="decisionRow"><span>Final URL</span><code style={{maxWidth:"62%",overflow:"hidden",textOverflow:"ellipsis"}}>{scan.finalUrl}</code></div>
        <div className="decisionRow"><span>HTTP Status</span><b>{scan.status}</b></div>
        <div className="decisionRow"><span>HTTPS</span><span className={`statusTag ${scan.https?"safe":"critical"}`}>{scan.https?"ACTIVE":"MISSING"}</span></div>
        <div className="decisionRow"><span>HTTP → HTTPS</span><span className={`statusTag ${scan.redirectedToHttps?"safe":"medium"}`}>{scan.redirectedToHttps?"ENFORCED":"NOT CONFIRMED"}</span></div>
        <div className="decisionRow"><span>Response</span><b>{scan.responseMs} ms</b></div>
        <div className="decisionRow"><span>Server</span><code>{scan.server || "Not exposed"}</code></div>
        <div className="decisionRow"><span>Technology</span><code>{scan.poweredBy || "Not exposed"}</code></div>
        {(scan.dns?.addresses || []).map((a,i)=><div className="decisionRow" key={`${a.address}-${i}`}><span>Resolved IP {i+1}</span><code>{a.address} · IPv{a.family}</code></div>)}
      </article>

      <article className="panel"><div className="panelHead"><div><h3>Security Layers</h3><p>Defensive controls observed on the scanned response.</p></div></div>
        {(scan.headers || []).map(h=><div className="decisionRow" key={h.key}><span>{h.label}</span><span className={`statusTag ${h.present?"safe":"medium"}`}>{h.present?"PRESENT":"MISSING"}</span></div>)}
        <div className="decisionRow"><span>CORS</span><code>{scan.cors || "Not exposed"}</code></div>
        <div className="decisionRow"><span>Cookies observed</span><b>{scan.cookies?.observed || 0}</b></div>
      </article>
    </div>

    <article className="panel" style={{marginTop:14}}><div className="panelHead"><div><h3>Potential Security Findings</h3><p>Passive posture findings, not proof of an exploitable vulnerability. Each item includes remediation guidance.</p></div><span className={`statusTag ${tagTone(scan.overallRisk)}`}>{scan.overallRisk} RISK</span></div>
      {(scan.findings || []).length ? scan.findings.slice(0,8).map((f,i)=><div className="eventRow" key={`${f.title}-${i}`} style={{alignItems:"flex-start"}}><span className={`statusTag ${tagTone(f.severity)}`}>{f.severity}</span><div style={{flex:1}}><b>{f.title}</b><small>{f.category} · {f.detail}</small><p style={{margin:"7px 0 3px",fontSize:11}}><strong>Impact:</strong> {f.impact}</p><p style={{margin:0,fontSize:11}}><strong>Fix:</strong> {f.fix}</p></div></div>) : <p>No material passive findings detected.</p>}
    </article>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Traffic Geography</h3><p>Country/city of real visitors cannot be derived from an external URL scan.</p></div><span className="statusTag medium">TRAFFIC ACCESS REQUIRED</span></div><div className="emptyMini"><Icon name="globe"/><b>No real visitor geography before integration</b><p>To show which country sends the most traffic, WebShield needs request logs, analytics access, or an edge/WAF collector.</p></div></article>
      <article className="panel"><div className="panelHead"><div><h3>Bot & Attack Intelligence</h3><p>Bot requests and attack attempts exist in traffic logs, not in the public homepage response.</p></div><span className="statusTag medium">TRAFFIC ACCESS REQUIRED</span></div><div className="emptyMini"><Icon name="threat"/><b>No bot/attack event evidence before integration</b><p>After connection, this section can show bot IPs, countries, request paths, risk scores, attack categories and blocking actions.</p></div></article>
    </div>
  </div>;
}

export function LiveTrafficIntelligencePage() {
  const [visitors,setVisitors]=useState<any[]>([]);
  const [threats,setThreats]=useState<any[]>([]);
  const [connected,setConnected]=useState(false);
  const [message,setMessage]=useState("");

  useEffect(()=>{
    Promise.all([fetch("/api/visitors",{cache:"no-store"}),fetch("/api/threats",{cache:"no-store"})]).then(async ([vr,tr])=>{
      const vb=await vr.json(); const tb=await tr.json();
      if(vr.ok&&vb.ok){setVisitors(Array.isArray(vb.data)?vb.data:[]);setConnected(true);} else setMessage(vb?.error?.message||"Traffic collector is not connected yet.");
      if(tr.ok&&tb.ok)setThreats(Array.isArray(tb.data)?tb.data:[]);
    }).catch(()=>setMessage("Traffic collector is not connected yet."));
  },[]);

  const countries=useMemo(()=>{
    const m=new Map<string,number>(); visitors.forEach(v=>m.set(v.country||"Unknown",(m.get(v.country||"Unknown")||0)+1)); return [...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8);
  },[visitors]);
  const botThreats=useMemo(()=>threats.filter(t=>/bot|crawler|automation/i.test(String(t.type||""))),[threats]);

  return <div className="pageWrap">
    <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Live Visitors</div><h1>Visitor & Traffic Intelligence</h1><p>External scan intelligence is available before integration. Real visitor IP, country, device, bot and request activity appears only after traffic/log access is connected.</p></div><span className={`statusTag ${connected?"safe":"medium"}`}>{connected?"BACKEND CONNECTED":"PRE-INTEGRATION"}</span></div>
    <PreIntegrationIntelligence compact/>

    <article className="panel" style={{marginTop:14}}><div className="panelHead"><div><h3>Connected Traffic Data</h3><p>{message || "Visitor records stored by the WebShield collector/provider."}</p></div><span className={`statusTag ${visitors.length?"safe":"medium"}`}>{visitors.length?`${visitors.length} VISITORS":"NO TRAFFIC DATA"}</span></div>
      {visitors.length ? <div className="tableScroll"><table><thead><tr><th>IP</th><th>Country / City</th><th>Device</th><th>Browser / OS</th><th>Referrer</th><th>Last Seen</th></tr></thead><tbody>{visitors.slice(0,50).map((v,i)=><tr key={v.id||i}><td><code>{v.ip_address||"—"}</code></td><td>{v.country||"Unknown"}<small>{v.city||""}</small></td><td>{v.device||"—"}</td><td>{v.browser||"—"}<small>{v.operating_system||""}</small></td><td>{v.referrer||"Direct/Unknown"}</td><td>{v.last_seen_at?new Date(v.last_seen_at).toLocaleString():"—"}</td></tr>)}</tbody></table></div> : <div className="formNotice">No visitor request logs are available yet. This is expected before a collector, analytics/log source, or edge/WAF integration is connected.</div>}
    </article>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Top Traffic Countries</h3><p>Calculated only from stored real visitor records.</p></div></div>{countries.length?countries.map(([country,count])=><div className="decisionRow" key={country}><span>{country}</span><b>{count}</b></div>):<p>No country traffic data yet.</p>}</article>
      <article className="panel"><div className="panelHead"><div><h3>Bot / Automation Events</h3><p>Calculated only from stored threat events.</p></div></div>{botThreats.length?botThreats.slice(0,10).map((t,i)=><div className="eventRow" key={t.id||i}><span className={`statusTag ${tagTone(t.severity||"LOW")}`}>{t.severity||"LOW"}</span><div><b>{t.type||"Bot activity"}</b><small>{t.source_ip||"Unknown IP"} · {t.target_url||"—"}</small></div></div>):<p>No real bot/automation events recorded yet.</p>}</article>
    </div>
  </div>;
}
