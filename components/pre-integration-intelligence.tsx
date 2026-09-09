"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { createClient } from "@/lib/supabase/client";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type Finding = { severity: Severity; category: string; title: string; detail: string; impact: string; fix: string };
type StoredScan = {
  requestedUrl: string; finalUrl: string; hostname: string; status: number; statusText?: string; responseMs: number;
  https: boolean; redirectedToHttps: boolean; securityScore: number; grade: string; overallRisk: Severity;
  findingCounts: Record<Severity, number>; findings: Finding[];
  headers: { key: string; label: string; present: boolean; value: string | null }[];
  server: string | null; poweredBy: string | null; cors: string | null;
  cookies: { observed: number; missingSecure: number; missingHttpOnly: number; missingSameSite: number };
  dns: { resolved: boolean; addresses: { address: string; family: number }[] };
  technologies: { signal: string; value: string }[]; scannedAt: string;
};

const STORAGE_KEY = "webshield:last-scan";

function useLatestScan() {
  const [scan, setScan] = useState<StoredScan | null>(null);
  useEffect(() => {
    const read = () => {
      try { const raw = window.localStorage.getItem(STORAGE_KEY); setScan(raw ? JSON.parse(raw) as StoredScan : null); }
      catch { setScan(null); }
    };
    read();
    window.addEventListener("storage", read);
    window.addEventListener("webshield:scan-updated", read as EventListener);
    return () => { window.removeEventListener("storage", read); window.removeEventListener("webshield:scan-updated", read as EventListener); };
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

function countBy<T>(items: T[], getter: (item: T) => string) {
  const map = new Map<string, number>();
  items.forEach(item => {
    const key = getter(item) || "Unknown";
    map.set(key, (map.get(key) || 0) + 1);
  });
  return [...map.entries()].sort((a,b)=>b[1]-a[1]);
}

function safePath(value: string) {
  if (!value) return "/";
  try { return new URL(value).pathname || "/"; } catch { return value.slice(0,120); }
}

function referrerLabel(value: string) {
  if (!value) return "Direct / Unknown";
  try { return new URL(value).hostname.replace(/^www\./, ""); } catch { return value.slice(0,80); }
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

    {!compact && <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Traffic Geography</h3><p>Country/city of real visitors requires connected traffic data.</p></div><span className="statusTag medium">TRAFFIC ACCESS REQUIRED</span></div><div className="emptyMini"><Icon name="globe"/><b>No real visitor geography before integration</b><p>Connect a WebShield collector, analytics source, or edge/WAF provider to populate this section.</p></div></article>
      <article className="panel"><div className="panelHead"><div><h3>Bot & Attack Intelligence</h3><p>Bot and attack evidence is based on connected traffic events.</p></div><span className="statusTag medium">TRAFFIC ACCESS REQUIRED</span></div><div className="emptyMini"><Icon name="threat"/><b>No connected threat evidence</b><p>Connected traffic can populate bot IPs, request paths, risk scores, event categories and actions.</p></div></article>
    </div>}
  </div>;
}

export function LiveTrafficIntelligencePage() {
  const [visitors,setVisitors]=useState<any[]>([]);
  const [sessions,setSessions]=useState<any[]>([]);
  const [threats,setThreats]=useState<any[]>([]);
  const [connected,setConnected]=useState(false);
  const [message,setMessage]=useState("");

  useEffect(()=>{
    const load = async () => {
      try {
        const supabase = createClient();
        const [vr,tr,sr] = await Promise.all([
          fetch("/api/visitors",{cache:"no-store"}),
          fetch("/api/threats",{cache:"no-store"}),
          supabase.from("visitor_sessions").select("id,website_id,visitor_id,requested_url,request_method,risk_score,status,occurred_at").order("occurred_at",{ascending:false}).limit(1000)
        ]);
        const vb=await vr.json(); const tb=await tr.json();
        if(vr.ok&&vb.ok){setVisitors(Array.isArray(vb.data)?vb.data:[]);setConnected(true);} else setMessage(vb?.error?.message||"Traffic collector is not connected yet.");
        if(tr.ok&&tb.ok)setThreats(Array.isArray(tb.data)?tb.data:[]);
        if(!sr.error)setSessions(Array.isArray(sr.data)?sr.data:[]);
      } catch {
        setMessage("Traffic intelligence could not be loaded.");
      }
    };
    load();
  },[]);

  const activeVisitors=useMemo(()=>{
    const cutoff=Date.now()-5*60*1000;
    return visitors.filter(v=>v.last_seen_at && new Date(v.last_seen_at).getTime()>=cutoff).length;
  },[visitors]);
  const countries=useMemo(()=>countBy(visitors,v=>v.country||"Unknown").slice(0,8),[visitors]);
  const cities=useMemo(()=>countBy(visitors,v=>v.city?`${v.city}, ${v.country||"Unknown"}`:"Unknown city").slice(0,8),[visitors]);
  const devices=useMemo(()=>countBy(visitors,v=>v.device||"Unknown").slice(0,6),[visitors]);
  const browsers=useMemo(()=>countBy(visitors,v=>v.browser||"Unknown").slice(0,6),[visitors]);
  const operatingSystems=useMemo(()=>countBy(visitors,v=>v.operating_system||"Unknown").slice(0,6),[visitors]);
  const referrers=useMemo(()=>countBy(visitors,v=>referrerLabel(v.referrer||"")).slice(0,8),[visitors]);
  const topPages=useMemo(()=>countBy(sessions,s=>safePath(s.requested_url||"")).slice(0,10),[sessions]);
  const botThreats=useMemo(()=>threats.filter(t=>/bot|crawler|automation|headless/i.test(String(t.type||""))),[threats]);
  const attackThreats=useMemo(()=>threats.filter(t=>!/bot|crawler|automation|headless/i.test(String(t.type||""))),[threats]);
  const severityCounts=useMemo(()=>countBy(threats,t=>String(t.severity||"UNKNOWN")).slice(0,5),[threats]);
  const maxRisk=useMemo(()=>threats.reduce((m,t)=>Math.max(m,Number(t.risk_score||0)),0),[threats]);
  const visitorMap=useMemo(()=>new Map(visitors.map(v=>[v.id,v])),[visitors]);

  return <div className="pageWrap">
    <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Live Visitors</div><h1>Visitor & Traffic Intelligence</h1><p>Real visitor geography, devices, sessions and stored threat events from the connected WebShield collector.</p></div><span className={`statusTag ${connected?"safe":"medium"}`}>{connected?"TRAFFIC CONNECTED":"PRE-INTEGRATION"}</span></div>
    <PreIntegrationIntelligence compact/>

    <div className="metricGrid compact" style={{marginTop:14}}>
      <article className="metricCard"><span>Unique Visitors</span><strong>{visitors.length}</strong><small>Stored real visitor records</small></article>
      <article className="metricCard"><span>Page Sessions</span><strong>{sessions.length}</strong><small>Collected page activity</small></article>
      <article className="metricCard"><span>Countries</span><strong>{countries.filter(([c])=>c!=="Unknown").length}</strong><small>{countries[0]?.[0]||"No geography yet"}</small></article>
      <article className="metricCard"><span>Active Visitors</span><strong>{activeVisitors}</strong><small>Seen in last 5 minutes</small></article>
    </div>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Traffic Geography</h3><p>Country and city distribution calculated from real connected visitors.</p></div><span className={`statusTag ${visitors.length?"safe":"medium"}`}>{visitors.length?"LIVE DATA":"NO DATA"}</span></div>
        <div className="decisionRow"><span>Top Country</span><b>{countries[0]?.[0]||"—"}</b></div>
        <div className="decisionRow"><span>Top City</span><b>{cities[0]?.[0]||"—"}</b></div>
        {countries.slice(0,5).map(([country,count])=><div className="decisionRow" key={country}><span>{country}</span><b>{count} · {visitors.length?Math.round((count/visitors.length)*100):0}%</b></div>)}
        {cities.slice(0,4).map(([city,count])=><div className="decisionRow" key={city}><span>{city}</span><b>{count}</b></div>)}
      </article>

      <article className="panel"><div className="panelHead"><div><h3>Bot & Attack Intelligence</h3><p>Only real stored detections are counted. No synthetic attack numbers.</p></div><span className={`statusTag ${threats.length?"critical":"safe"}`}>{threats.length?`${threats.length} EVENTS`:"0 DETECTED"}</span></div>
        <div className="decisionRow"><span>Bot / Automation</span><b>{botThreats.length}</b></div>
        <div className="decisionRow"><span>Other Threat Events</span><b>{attackThreats.length}</b></div>
        <div className="decisionRow"><span>Highest Risk Score</span><b>{maxRisk}/100</b></div>
        <div className="decisionRow"><span>Blocked Events</span><b>{threats.filter(t=>String(t.action_taken||"").toUpperCase()==="BLOCK"||String(t.status||"").toUpperCase()==="BLOCKED").length}</b></div>
        {severityCounts.map(([severity,count])=><div className="decisionRow" key={severity}><span>{severity}</span><b>{count}</b></div>)}
        {!threats.length && <p style={{marginTop:12}}>Collector is active. No bot/automation or stored threat event has been detected in the captured traffic yet.</p>}
      </article>
    </div>

    <article className="panel" style={{marginTop:14}}><div className="panelHead"><div><h3>Connected Traffic Data</h3><p>{message || "Visitor records stored by the WebShield collector/provider."}</p></div><span className={`statusTag ${visitors.length?"safe":"medium"}`}>{visitors.length ? `${visitors.length} VISITORS` : "NO TRAFFIC DATA"}</span></div>
      {visitors.length ? <div className="tableScroll"><table><thead><tr><th>IP</th><th>Country / City</th><th>Device</th><th>Browser / OS</th><th>Referrer</th><th>Last Seen</th></tr></thead><tbody>{visitors.slice(0,50).map((v,i)=><tr key={v.id||i}><td><code>{v.ip_address||"—"}</code></td><td>{v.country||"Unknown"}<small>{v.city||""}</small></td><td>{v.device||"—"}</td><td>{v.browser||"—"}<small>{v.operating_system||""}</small></td><td>{referrerLabel(v.referrer||"")}</td><td>{v.last_seen_at?new Date(v.last_seen_at).toLocaleString():"—"}</td></tr>)}</tbody></table></div> : <div className="formNotice">No visitor request logs are available yet.</div>}
    </article>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Device & Browser Mix</h3><p>Real visitor client signals.</p></div></div>
        <b style={{display:"block",marginBottom:8}}>Devices</b>{devices.map(([name,count])=><div className="decisionRow" key={`d-${name}`}><span>{name}</span><b>{count}</b></div>)}
        <b style={{display:"block",margin:"14px 0 8px"}}>Browsers</b>{browsers.map(([name,count])=><div className="decisionRow" key={`b-${name}`}><span>{name}</span><b>{count}</b></div>)}
        <b style={{display:"block",margin:"14px 0 8px"}}>Operating Systems</b>{operatingSystems.map(([name,count])=><div className="decisionRow" key={`o-${name}`}><span>{name}</span><b>{count}</b></div>)}
      </article>

      <article className="panel"><div className="panelHead"><div><h3>Top Pages & Referrers</h3><p>Most observed paths and traffic sources from collected sessions.</p></div></div>
        <b style={{display:"block",marginBottom:8}}>Top Pages</b>{topPages.length?topPages.slice(0,6).map(([page,count])=><div className="decisionRow" key={`p-${page}`}><span><code>{page}</code></span><b>{count}</b></div>):<p>No page activity yet.</p>}
        <b style={{display:"block",margin:"14px 0 8px"}}>Referrers</b>{referrers.slice(0,6).map(([ref,count])=><div className="decisionRow" key={`r-${ref}`}><span>{ref}</span><b>{count}</b></div>)}
      </article>
    </div>

    <article className="panel" style={{marginTop:14}}><div className="panelHead"><div><h3>Recent Page Activity</h3><p>Latest real page/session events captured by WebShield.</p></div><span className="statusTag safe">{sessions.length} SESSIONS</span></div>
      {sessions.length ? <div className="tableScroll"><table><thead><tr><th>Page</th><th>Visitor</th><th>Location</th><th>Status</th><th>Risk</th><th>Time</th></tr></thead><tbody>{sessions.slice(0,50).map((s,i)=>{const v=visitorMap.get(s.visitor_id);return <tr key={s.id||i}><td><code>{safePath(s.requested_url||"")}</code></td><td><code>{v?.ip_address||"—"}</code></td><td>{v?.country||"Unknown"}<small>{v?.city||""}</small></td><td>{s.status||"—"}</td><td>{Number(s.risk_score||0)}/100</td><td>{s.occurred_at?new Date(s.occurred_at).toLocaleString():"—"}</td></tr>})}</tbody></table></div> : <p>No page sessions recorded yet.</p>}
    </article>

    <div className="dashboardGrid equal" style={{marginTop:14}}>
      <article className="panel"><div className="panelHead"><div><h3>Top Traffic Countries</h3><p>Calculated only from stored real visitor records.</p></div></div>{countries.length?countries.map(([country,count])=><div className="decisionRow" key={country}><span>{country}</span><b>{count}</b></div>):<p>No country traffic data yet.</p>}</article>
      <article className="panel"><div className="panelHead"><div><h3>Recent Bot / Threat Events</h3><p>Real events stored by WebShield detection logic.</p></div></div>{threats.length?threats.slice(0,10).map((t,i)=><div className="eventRow" key={t.id||i}><span className={`statusTag ${tagTone(t.severity||"LOW")}`}>{t.severity||"LOW"}</span><div><b>{t.type||"Security event"}</b><small>{t.source_ip||"Unknown IP"} · {safePath(t.target_url||"")} · Risk {Number(t.risk_score||0)}/100 · {t.action_taken||"MONITOR"}</small></div></div>):<p>No real bot/automation or attack events recorded yet.</p>}</article>
    </div>
  </div>;
}
