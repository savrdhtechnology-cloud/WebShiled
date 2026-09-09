"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { WebsiteScanner } from "@/components/website-scanner";
import { PreIntegrationIntelligence } from "@/components/pre-integration-intelligence";

type WebsiteRow = {
  id:string; domain:string; status:string; verified_at:string|null; ssl_status:string|null;
  integration_status:string|null; last_event_at:string|null; created_at:string;
};
type VisitorRow = {
  id:string; website_id:string; country:string|null; city:string|null; device:string|null;
  browser:string|null; operating_system:string|null; referrer:string|null; first_seen_at:string; last_seen_at:string;
};
type SessionRow = {
  id:string; website_id:string; visitor_id:string; requested_url:string|null; status:string|null;
  risk_score:number|null; occurred_at:string;
};
type ThreatRow = Record<string, any>;
type AlertRow = Record<string, any>;
type DashboardData = {
  metrics?: { websites:number; visitors:number; activeVisitors:number; threats:number; blockedRequests:number; openAlerts:number };
  threats?: ThreatRow[];
  alerts?: AlertRow[];
  websitesData?: WebsiteRow[];
  visitorsData?: VisitorRow[];
  sessionsData?: SessionRow[];
  organizationId?: string;
  websites?: number;
  threatsCount?: number;
  openAlerts?: number;
  openTickets?: number;
};
type StoredScan = {
  hostname:string; securityScore:number; grade:string; overallRisk:string; scannedAt:string;
  findings?: Array<{severity:string;title:string;category:string}>;
  headers?: Array<{key:string;label:string;present:boolean}>;
};

function Notice({ message }: { message: string }) {
  return <article className="panel" style={{marginTop:16}}><div className="panelHead"><div><h3>Connected Traffic Status</h3><p>{message}</p></div><span className="statusTag medium">TRAFFIC ACCESS REQUIRED</span></div><p>External scan intelligence is real. Visitor IPs, country traffic, bot requests and attack events require request/log access from the protected website.</p><div className="buttonRow"><Link href="/register" className="btn small">Create real account</Link><Link href="/app/live-visitors" className="ghostBtn small">Traffic Intelligence</Link></div></article>;
}

function AnimatedNumber({ value, suffix = "" }: { value:number; suffix?:string }) {
  const [shown,setShown]=useState(0);
  useEffect(()=>{
    const start=performance.now();
    const duration=650;
    let frame=0;
    const tick=(now:number)=>{
      const p=Math.min(1,(now-start)/duration);
      setShown(Math.round(value*(1-Math.pow(1-p,3))));
      if(p<1) frame=requestAnimationFrame(tick);
    };
    frame=requestAnimationFrame(tick);
    return ()=>cancelAnimationFrame(frame);
  },[value]);
  return <>{shown}{suffix}</>;
}

function safePath(url?:string|null){
  if(!url) return "/";
  try{return new URL(url).pathname || "/";}catch{return url.split("?")[0] || "/";}
}

function ago(value?:string|null){
  if(!value) return "No recent event";
  const diff=Math.max(0,Date.now()-new Date(value).getTime());
  const min=Math.floor(diff/60000);
  if(min<1) return "Just now";
  if(min<60) return `${min}m ago`;
  const hr=Math.floor(min/60);
  if(hr<24) return `${hr}h ago`;
  return `${Math.floor(hr/24)}d ago`;
}

function QuickScan({initialDomain,onScan}:{initialDomain:string;onScan:(scan:StoredScan)=>void}){
  const [url,setUrl]=useState(initialDomain);
  const [loading,setLoading]=useState(false);
  const [message,setMessage]=useState("");
  useEffect(()=>{if(!url&&initialDomain)setUrl(initialDomain);},[initialDomain,url]);
  async function submit(e:FormEvent){
    e.preventDefault(); setLoading(true); setMessage("");
    try{
      const r=await fetch("/api/scan",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({url})});
      const b=await r.json();
      if(!r.ok||!b?.ok) throw new Error(b?.error||"Scan failed.");
      const scan=b.scan as StoredScan;
      try{localStorage.setItem("webshield:last-scan",JSON.stringify(scan));window.dispatchEvent(new Event("webshield:scan-updated"));}catch{}
      onScan(scan); setMessage(`Scan complete · ${scan.securityScore}/100 · ${scan.overallRisk} risk`);
    }catch(e){setMessage(e instanceof Error?e.message:"Scan failed.");}
    finally{setLoading(false);}
  }
  return <form className="cockpitScan" onSubmit={submit}>
    <div><span>QUICK SECURITY SCAN</span><b>Check current public security posture</b></div>
    <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="example.com" required/>
    <button className="btn small" disabled={loading}>{loading?"Scanning…":"Run scan"}</button>
    {message&&<small>{message}</small>}
  </form>;
}

function TrafficLine({sessions}:{sessions:SessionRow[]}){
  const buckets=useMemo(()=>{
    const now=new Date(); now.setMinutes(0,0,0);
    const arr=Array.from({length:12},(_,i)=>({time:new Date(now.getTime()-(11-i)*3600000),count:0}));
    sessions.forEach(s=>{
      const t=new Date(s.occurred_at).getTime();
      arr.forEach((b,i)=>{const start=b.time.getTime(),end=start+3600000;if(t>=start&&t<end)arr[i].count++;});
    });
    return arr;
  },[sessions]);
  const max=Math.max(1,...buckets.map(b=>b.count));
  const points=buckets.map((b,i)=>`${18+i*(364/(buckets.length-1))},${128-(b.count/max)*94}`).join(" ");
  const area=`18,128 ${points} 382,128`;
  return <div className="trafficChart">
    <div className="chartGridLines"><i/><i/><i/><i/></div>
    <svg viewBox="0 0 400 150" preserveAspectRatio="none" aria-label="Traffic activity chart">
      <defs><linearGradient id="trafficGlow" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#20d9ff" stopOpacity=".35"/><stop offset="100%" stopColor="#20d9ff" stopOpacity="0"/></linearGradient></defs>
      <polygon points={area} fill="url(#trafficGlow)"/>
      <polyline className="trafficLinePath" points={points} fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
      {buckets.map((b,i)=><circle key={i} cx={18+i*(364/(buckets.length-1))} cy={128-(b.count/max)*94} r="3" fill="#07111d" stroke="#20d9ff" strokeWidth="2"/>)}
    </svg>
    <div className="chartAxis"><span>{buckets[0].time.toLocaleTimeString([],{hour:"numeric"})}</span><span>Last 12 hours</span><span>Now</span></div>
  </div>;
}

function Ring({value,label}:{value:number;label:string}){
  const safe=Math.max(0,Math.min(100,value));
  return <div className="scoreRing" style={{background:`conic-gradient(#20d9ff ${safe*3.6}deg, rgba(75,113,139,.18) 0deg)`}}><div><strong><AnimatedNumber value={safe}/></strong><span>/100</span><small>{label}</small></div></div>;
}

function Bars({items,total}:{items:Array<[string,number]>;total:number}){
  if(!items.length)return <div className="cockpitEmpty">No data captured yet.</div>;
  return <div className="miniBars">{items.slice(0,5).map(([name,count])=>{const pct=total?Math.round(count/total*100):0;return <div key={name}><div><span>{name}</span><b>{count} · {pct}%</b></div><i><em style={{width:`${pct}%`}}/></i></div>;})}</div>;
}

export function BackendDashboard({ admin = false }: { admin?: boolean }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [scan,setScan]=useState<StoredScan|null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(admin ? "/api/admin" : "/api/dashboard", { cache: "no-store" })
      .then(async r => {const body=await r.json();if(!r.ok||!body.ok)throw new Error(body?.error?.message||"Connected backend data unavailable.");return body.data;})
      .then(setData).catch(e=>setError(e instanceof Error?e.message:"Connected backend data unavailable."))
      .finally(()=>setLoading(false));
    if(!admin){try{const raw=localStorage.getItem("webshield:last-scan");if(raw)setScan(JSON.parse(raw));}catch{}}
  }, [admin]);

  if (admin) {
    const stats = data ? [
      ["Websites", String(data.websites ?? 0), "Database records", "globe"],
      ["Threat Events", String(data.threatsCount ?? 0), "Database records", "threat"],
      ["Open Alerts", String(data.openAlerts ?? 0), "Needs review", "bell"],
      ["Open Tickets", String(data.openTickets ?? 0), "Support queue", "visitors"]
    ] : [];
    return <div className="pageWrap">
      <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Administration</div><h1>Admin Dashboard</h1><p>Scan websites, review external security posture and manage connected WebShield backend records.</p></div><span className="statusTag safe">SCAN + BACKEND</span></div>
      <WebsiteScanner/><PreIntegrationIntelligence compact/>
      {loading&&<article className="panel" style={{marginTop:16}}><p>Loading connected backend data…</p></article>}{error&&<Notice message={error}/>} 
      {data&&<><div className="metricGrid compact" style={{marginTop:16}}>{stats.map(([label,value,note,icon])=><article className="metricCard" key={label}><div className="metricTop"><span>{label}</span><div className="metricIcon"><Icon name={icon}/></div></div><strong>{value}</strong><small>{note}</small></article>)}</div><article className="panel" style={{marginTop:16}}><div className="panelHead"><div><h3>Essential administration</h3><p>Only high-value platform modules are kept in the sidebar.</p></div></div><div className="endpointGrid"><Link href="/admin/websites">Websites</Link><Link href="/admin/security-events">Security Events</Link><Link href="/admin/plans">Plans & Billing</Link><Link href="/admin/support-tickets">Support</Link><Link href="/admin/system-settings">Settings</Link></div></article></>}
    </div>;
  }

  const m=data?.metrics;
  const websites=data?.websitesData||[];
  const visitors=data?.visitorsData||[];
  const sessions=data?.sessionsData||[];
  const threats=data?.threats||[];
  const alerts=data?.alerts||[];
  const activeSite=websites.find(w=>w.integration_status==="COLLECTOR_CONNECTED")||websites[0];
  const countryData=useMemo(()=>{const map=new Map<string,number>();visitors.forEach(v=>{const k=v.country||"Unknown";map.set(k,(map.get(k)||0)+1);});return [...map.entries()].sort((a,b)=>b[1]-a[1]);},[visitors]);
  const deviceData=useMemo(()=>{const map=new Map<string,number>();visitors.forEach(v=>{const k=v.device||"Unknown";map.set(k,(map.get(k)||0)+1);});return [...map.entries()].sort((a,b)=>b[1]-a[1]);},[visitors]);
  const pageData=useMemo(()=>{const map=new Map<string,number>();sessions.forEach(s=>{const k=safePath(s.requested_url);map.set(k,(map.get(k)||0)+1);});return [...map.entries()].sort((a,b)=>b[1]-a[1]);},[sessions]);
  const severityData=useMemo(()=>{const map=new Map<string,number>();threats.forEach(t=>{const k=String(t.severity||"LOW").toUpperCase();map.set(k,(map.get(k)||0)+1);});return [...map.entries()].sort((a,b)=>b[1]-a[1]);},[threats]);
  const presentLayers=scan?.headers?.filter(h=>h.present).length||0;
  const totalLayers=scan?.headers?.length||0;
  const score=scan?.securityScore??0;
  const connectionReady=Boolean(activeSite?.integration_status==="COLLECTOR_CONNECTED");
  const verified=Boolean(activeSite?.verified_at);

  return <div className="pageWrap cockpitPage">
    <section className="cockpitHero">
      <div>
        <div className="breadcrumbs">WebShield <span>/</span> Security Operations</div>
        <div className="cockpitTitle"><div><h1>Security Command Center</h1><p>Live website intelligence, visitor telemetry and security posture in one operational view.</p></div><span className={`liveOrb ${connectionReady?"on":""}`}><i/>{connectionReady?"LIVE MONITORING":"MONITORING SETUP"}</span></div>
      </div>
      <div className="cockpitWebsite"><span className="sitePulse"><Icon name="globe"/></span><div><small>PRIMARY WEBSITE</small><strong>{activeSite?.domain||scan?.hostname||"No website connected"}</strong><span>{connectionReady?`Collector connected · ${ago(activeSite?.last_event_at)}`:"Connect a website to begin live telemetry"}</span></div><div className="heroActionsMini"><Link href="/app/websites" className="ghostBtn small">Manage website</Link><Link href="/app/live-visitors" className="btn small">Live traffic</Link></div></div>
    </section>

    <QuickScan initialDomain={activeSite?.domain||scan?.hostname||""} onScan={setScan}/>

    {loading&&<div className="cockpitLoading"><span/><p>Loading security telemetry…</p></div>}
    {error&&<Notice message={error}/>} 
    {m&&<>
      <section className="cockpitKpis">
        {[
          {label:"Unique Visitors",value:m.visitors,note:"Real visitor records",icon:"visitors",tone:"cyan"},
          {label:"Page Sessions",value:sessions.length,note:"Recent captured requests",icon:"chart",tone:"blue"},
          {label:"Active Now",value:m.activeVisitors,note:"Seen in last 5 min",icon:"globe",tone:"green"},
          {label:"Threat Events",value:m.threats,note:"Detected security events",icon:"threat",tone:m.threats?"orange":"green"},
          {label:"Blocked",value:m.blockedRequests,note:"Blocked sessions",icon:"firewall",tone:m.blockedRequests?"orange":"green"},
          {label:"Open Alerts",value:m.openAlerts,note:"Need review",icon:"bell",tone:m.openAlerts?"orange":"green"}
        ].map(k=><article className={`cockpitKpi ${k.tone}`} key={k.label}><div><span>{k.label}</span><b><AnimatedNumber value={k.value}/></b><small>{k.note}</small></div><i><Icon name={k.icon} size={20}/></i></article>)}
      </section>

      <section className="cockpitMainGrid">
        <article className="cockpitCard trafficPanel">
          <header><div><span>TRAFFIC ACTIVITY</span><h3>Visitor sessions trend</h3><p>Real page-session activity captured during the last 12 hours.</p></div><Link href="/app/live-visitors">Explore traffic →</Link></header>
          <div className="trafficSummary"><strong><AnimatedNumber value={sessions.length}/></strong><span>captured sessions in current dataset</span><em>{m.activeVisitors} active now</em></div>
          <TrafficLine sessions={sessions}/>
        </article>

        <article className="cockpitCard scorePanel">
          <header><div><span>SECURITY POSTURE</span><h3>Current scan score</h3></div><Link href="/app/websites">Full scan →</Link></header>
          <div className="scoreBody"><Ring value={score} label={scan?`Grade ${scan.grade}`:"No scan"}/><div className="scoreMeta"><div><span>Risk level</span><b className={`riskText ${(scan?.overallRisk||"info").toLowerCase()}`}>{scan?.overallRisk||"NOT SCANNED"}</b></div><div><span>Security layers</span><b>{presentLayers}/{totalLayers||"—"}</b></div><div><span>Findings</span><b>{scan?.findings?.length||0}</b></div><div><span>Last scan</span><b>{scan?ago(scan.scannedAt):"—"}</b></div></div></div>
        </article>
      </section>

      <section className="cockpitTripleGrid">
        <article className="cockpitCard"><header><div><span>TRAFFIC GEOGRAPHY</span><h3>Top countries</h3><p>Based on real visitor location headers.</p></div><span className="dataBadge">{countryData.length} COUNTRIES</span></header><Bars items={countryData} total={visitors.length}/><div className="cardFoot"><Link href="/app/live-visitors">Open geography intelligence →</Link></div></article>
        <article className="cockpitCard"><header><div><span>DEVICE INTELLIGENCE</span><h3>Visitor device mix</h3><p>Desktop, mobile and other devices.</p></div><Icon name="visitors"/></header><Bars items={deviceData} total={visitors.length}/><div className="cardFoot"><span>Top browser: <b>{visitors[0]?.browser||"—"}</b></span></div></article>
        <article className="cockpitCard"><header><div><span>PROTECTION READINESS</span><h3>Security activation</h3><p>Current integration state.</p></div><Icon name="shield"/></header><div className="readinessSteps">
          {[
            ["Website added",Boolean(activeSite)],
            ["Security scan",Boolean(scan)],
            ["Ownership verified",verified],
            ["Traffic collector",connectionReady],
            ["Threat telemetry",sessions.length>0]
          ].map(([label,done],i)=><div className={done?"done":""} key={String(label)}><i>{done?<Icon name="check" size={12}/>:i+1}</i><span>{label}</span><b>{done?"READY":"PENDING"}</b></div>)}
        </div></article>
      </section>

      <section className="cockpitMainGrid lower">
        <article className="cockpitCard"><header><div><span>TOP CONTENT</span><h3>Most visited pages</h3><p>Page activity from stored sessions.</p></div><Icon name="chart"/></header><div className="pageRanks">{pageData.length?pageData.slice(0,6).map(([page,count],i)=><div key={page}><i>{String(i+1).padStart(2,"0")}</i><span title={page}>{page}</span><b>{count}</b></div>):<div className="cockpitEmpty">No page activity yet.</div>}</div></article>
        <article className="cockpitCard"><header><div><span>THREAT INTELLIGENCE</span><h3>Detection overview</h3><p>Only real stored threat events are shown.</p></div><Link href="/app/threat-center">Threat Center →</Link></header>{threats.length?<><Bars items={severityData} total={threats.length}/><div className="recentThreats">{threats.slice(0,3).map(t=><div key={t.id}><span className={`threatDot ${(t.severity||"low").toLowerCase()}`}/><div><b>{t.type||"Threat event"}</b><small>{t.target_url?safePath(t.target_url):"Unknown target"} · risk {t.risk_score??0}</small></div><em>{ago(t.occurred_at)}</em></div>)}</div></>:<div className="cleanState"><span><Icon name="shield" size={26}/></span><b>No threat events recorded</b><p>Current collected traffic has not produced a stored threat event.</p></div>}</article>
      </section>

      <section className="cockpitBottomGrid">
        <article className="cockpitCard"><header><div><span>RECENT VISITORS</span><h3>Latest activity</h3></div><Link href="/app/live-visitors">View all →</Link></header><div className="activityList">{visitors.length?visitors.slice(0,5).map(v=><div key={v.id}><span className="activityAvatar">{(v.country||"?").slice(0,2)}</span><div><b>{v.city||"Unknown city"}, {v.country||"Unknown"}</b><small>{v.device||"Unknown device"} · {v.browser||"Unknown browser"} · {v.operating_system||"Unknown OS"}</small></div><em>{ago(v.last_seen_at)}</em></div>):<div className="cockpitEmpty">No visitors captured yet.</div>}</div></article>
        <article className="cockpitCard"><header><div><span>SECURITY ALERTS</span><h3>Needs attention</h3></div><Link href="/app/alerts">View alerts →</Link></header><div className="activityList alerts">{alerts.length?alerts.slice(0,5).map(a=><div key={a.id}><span className={`activityAlert ${(a.severity||"low").toLowerCase()}`}><Icon name="bell" size={14}/></span><div><b>{a.title||a.type||"Security alert"}</b><small>{a.message||"No additional details"}</small></div><em>{a.acknowledged_at?"ACK":"OPEN"}</em></div>):<div className="cleanState compact"><span><Icon name="check" size={18}/></span><b>No open alert records</b></div>}</div></article>
      </section>
    </>}

    <style jsx global>{`
      .cockpitPage{padding-bottom:48px}.cockpitHero{position:relative;overflow:hidden;padding:24px 26px;margin-bottom:14px;border:1px solid rgba(86,180,222,.16);border-radius:18px;background:radial-gradient(circle at 80% 0,rgba(32,217,255,.12),transparent 34%),linear-gradient(135deg,#0b1827,#07111d 62%);box-shadow:0 24px 65px rgba(0,0,0,.22)}.cockpitHero:after{content:"";position:absolute;right:-60px;top:-90px;width:280px;height:280px;border:1px solid rgba(32,217,255,.08);border-radius:50%;box-shadow:0 0 0 45px rgba(32,217,255,.025),0 0 0 90px rgba(32,217,255,.015)}.cockpitTitle{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-top:6px;position:relative;z-index:1}.cockpitTitle h1{margin:3px 0 4px;font-size:32px;letter-spacing:-1.5px}.cockpitTitle p{margin:0;font-size:11px}.liveOrb{display:flex;align-items:center;gap:8px;white-space:nowrap;border:1px solid rgba(255,177,74,.25);background:rgba(255,177,74,.06);color:#ffbd69;padding:8px 10px;border-radius:999px;font-size:8px;font-weight:900;letter-spacing:.8px}.liveOrb i{width:7px;height:7px;border-radius:50%;background:#ffb14a}.liveOrb.on{color:#62e9b2;border-color:rgba(62,228,155,.25);background:rgba(62,228,155,.06)}.liveOrb.on i{background:#3ee49b;box-shadow:0 0 14px rgba(62,228,155,.75);animation:wsPulse 1.8s infinite}.cockpitWebsite{position:relative;z-index:1;display:flex;align-items:center;gap:12px;margin-top:22px;padding-top:18px;border-top:1px solid rgba(120,190,225,.1)}.sitePulse{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:rgba(32,217,255,.08);border:1px solid rgba(32,217,255,.17);color:#20d9ff}.cockpitWebsite>div:nth-child(2){display:flex;flex-direction:column;min-width:0}.cockpitWebsite small{font-size:7px;letter-spacing:1.5px;color:#58778d;font-weight:900}.cockpitWebsite strong{font-size:13px;margin:3px 0}.cockpitWebsite span{font-size:9px;color:#7894a8}.heroActionsMini{margin-left:auto;display:flex;gap:8px}.cockpitScan{display:grid;grid-template-columns:minmax(190px,.65fr) 1fr auto;align-items:center;gap:12px;padding:13px 15px;margin-bottom:14px;border:1px solid rgba(120,190,225,.13);border-radius:14px;background:#091522}.cockpitScan>div{display:flex;flex-direction:column}.cockpitScan>div span{color:#20d9ff;font-size:7px;letter-spacing:1.4px;font-weight:900}.cockpitScan>div b{font-size:10px;margin-top:3px}.cockpitScan input{height:38px;border:1px solid rgba(120,190,225,.14);border-radius:9px;background:#07111c;color:#dff7ff;padding:0 12px;outline:none}.cockpitScan input:focus{border-color:rgba(32,217,255,.4)}.cockpitScan>small{grid-column:2/4;color:#72b9ce;font-size:8px}.cockpitLoading{display:flex;align-items:center;gap:10px;padding:15px;border:1px solid rgba(120,190,225,.1);border-radius:12px;background:#091522}.cockpitLoading span{width:14px;height:14px;border:2px solid rgba(32,217,255,.2);border-top-color:#20d9ff;border-radius:50%;animation:wsSpin .75s linear infinite}.cockpitLoading p{margin:0;font-size:10px}.cockpitKpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:14px 0}.cockpitKpi{position:relative;display:flex;justify-content:space-between;min-height:114px;padding:16px;border:1px solid rgba(120,190,225,.13);border-radius:14px;background:linear-gradient(145deg,#0c1928,#08131f);overflow:hidden;transition:.25s}.cockpitKpi:hover{transform:translateY(-2px);border-color:rgba(32,217,255,.28)}.cockpitKpi:after{content:"";position:absolute;width:70px;height:70px;right:-25px;bottom:-30px;border-radius:50%;background:rgba(32,217,255,.06);filter:blur(4px)}.cockpitKpi>div{display:flex;flex-direction:column;z-index:1}.cockpitKpi span{font-size:8px;color:#7893a7}.cockpitKpi b{font-size:27px;line-height:1;margin:12px 0 8px;letter-spacing:-1px}.cockpitKpi small{font-size:7px;color:#577489}.cockpitKpi>i{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:rgba(32,217,255,.06);color:#20d9ff}.cockpitKpi.green>i{color:#3ee49b;background:rgba(62,228,155,.07)}.cockpitKpi.orange>i{color:#ffb14a;background:rgba(255,177,74,.08)}.cockpitKpi.blue>i{color:#6b8fff;background:rgba(67,140,255,.09)}.cockpitMainGrid{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(300px,.8fr);gap:12px;margin-bottom:12px}.cockpitMainGrid.lower{grid-template-columns:1.15fr .85fr}.cockpitTripleGrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:12px}.cockpitBottomGrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cockpitCard{position:relative;padding:18px;border:1px solid rgba(120,190,225,.13);border-radius:15px;background:linear-gradient(145deg,rgba(12,25,40,.96),rgba(7,17,29,.98));box-shadow:0 20px 55px rgba(0,0,0,.15);overflow:hidden}.cockpitCard header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}.cockpitCard header span{display:block;color:#20d9ff;font-size:7px;letter-spacing:1.4px;font-weight:900}.cockpitCard header h3{font-size:14px;margin:4px 0 2px}.cockpitCard header p{font-size:8px;margin:0}.cockpitCard header>a,.cardFoot>a{font-size:8px;color:#4fdfff;white-space:nowrap}.cockpitCard header>svg{color:#41677e}.trafficSummary{display:flex;align-items:baseline;gap:8px;margin:8px 0 0}.trafficSummary strong{font-size:27px}.trafficSummary span{font-size:8px;color:#6f899d}.trafficSummary em{margin-left:auto;font-style:normal;font-size:8px;color:#56e4aa}.trafficChart{position:relative;height:190px;margin-top:4px}.trafficChart svg{position:absolute;inset:12px 0 22px;width:100%;height:150px;color:#20d9ff;z-index:2}.trafficLinePath{stroke-dasharray:900;stroke-dashoffset:900;animation:wsDraw 1.3s ease forwards;filter:drop-shadow(0 0 5px rgba(32,217,255,.35))}.chartGridLines{position:absolute;inset:20px 0 35px;display:flex;flex-direction:column;justify-content:space-between}.chartGridLines i{border-top:1px dashed rgba(120,190,225,.08)}.chartAxis{position:absolute;left:0;right:0;bottom:0;display:flex;justify-content:space-between;color:#4f6b7e;font-size:7px}.scoreBody{display:grid;grid-template-columns:150px 1fr;align-items:center;gap:14px;padding-top:8px}.scoreRing{width:138px;height:138px;border-radius:50%;display:grid;place-items:center;animation:wsPop .6s ease both;box-shadow:0 0 35px rgba(32,217,255,.07)}.scoreRing>div{width:104px;height:104px;border-radius:50%;display:grid;place-content:center;text-align:center;background:#091522;box-shadow:inset 0 0 35px rgba(0,0,0,.32)}.scoreRing strong{font-size:31px;line-height:1}.scoreRing span{font-size:8px;color:#7894a8}.scoreRing small{margin-top:5px;color:#20d9ff;font-size:8px}.scoreMeta{display:grid;gap:7px}.scoreMeta>div{display:flex;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid rgba(120,190,225,.08)}.scoreMeta span{font-size:8px;color:#69859a}.scoreMeta b{font-size:9px}.riskText.medium{color:#ffb14a}.riskText.high,.riskText.critical{color:#ff647d}.riskText.low,.riskText.info{color:#6ce8b6}.dataBadge{padding:5px 7px;border:1px solid rgba(32,217,255,.18);border-radius:999px;background:rgba(32,217,255,.05);font-size:7px!important;color:#72e6fa!important}.miniBars{display:grid;gap:11px}.miniBars>div>div{display:flex;justify-content:space-between;margin-bottom:5px}.miniBars span,.miniBars b{font-size:8px}.miniBars span{color:#9bb0bf}.miniBars b{color:#6d899c}.miniBars i{display:block;height:5px;border-radius:999px;background:rgba(97,140,164,.12);overflow:hidden}.miniBars em{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#20d9ff,#438cff);box-shadow:0 0 10px rgba(32,217,255,.25);animation:wsBar .8s ease both}.cardFoot{margin-top:14px;padding-top:12px;border-top:1px solid rgba(120,190,225,.08);font-size:8px;color:#607e92}.cardFoot b{color:#a9c4d5}.readinessSteps{display:grid;gap:7px}.readinessSteps>div{display:grid;grid-template-columns:25px 1fr auto;align-items:center;gap:8px;padding:7px 8px;border:1px solid rgba(120,190,225,.08);border-radius:9px;background:rgba(5,13,22,.35)}.readinessSteps i{width:23px;height:23px;border-radius:7px;display:grid;place-items:center;font-style:normal;font-size:8px;background:#101e2c;color:#627f94}.readinessSteps span{font-size:8px;color:#7892a5}.readinessSteps b{font-size:7px;color:#637f92}.readinessSteps .done{border-color:rgba(62,228,155,.12)}.readinessSteps .done i{color:#3ee49b;background:rgba(62,228,155,.07)}.readinessSteps .done b{color:#54daa4}.pageRanks{display:grid}.pageRanks>div{display:grid;grid-template-columns:28px 1fr 35px;align-items:center;gap:8px;padding:10px 0;border-bottom:1px solid rgba(120,190,225,.08)}.pageRanks i{font-style:normal;font-size:7px;color:#45677e}.pageRanks span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:9px;color:#a8bbc9}.pageRanks b{text-align:right;font-size:9px;color:#20d9ff}.recentThreats{display:grid;margin-top:13px}.recentThreats>div{display:grid;grid-template-columns:8px 1fr auto;gap:8px;align-items:center;padding:9px 0;border-top:1px solid rgba(120,190,225,.08)}.threatDot{width:6px;height:6px;border-radius:50%;background:#5e7890}.threatDot.high,.threatDot.critical{background:#ff526e;box-shadow:0 0 8px rgba(255,82,110,.45)}.threatDot.medium{background:#ffb14a}.recentThreats b{display:block;font-size:8px}.recentThreats small{display:block;color:#617f93;font-size:7px;margin-top:2px}.recentThreats em{font-style:normal;color:#567387;font-size:7px}.cleanState{min-height:150px;display:grid;place-items:center;align-content:center;text-align:center}.cleanState span{width:44px;height:44px;display:grid;place-items:center;border-radius:12px;background:rgba(62,228,155,.07);color:#3ee49b}.cleanState b{margin-top:9px;font-size:10px}.cleanState p{font-size:8px;max-width:270px;margin:4px auto}.cleanState.compact{min-height:90px}.activityList{display:grid}.activityList>div{display:grid;grid-template-columns:32px 1fr auto;align-items:center;gap:9px;padding:9px 0;border-bottom:1px solid rgba(120,190,225,.08)}.activityAvatar,.activityAlert{width:29px;height:29px;border-radius:9px;display:grid;place-items:center;background:rgba(32,217,255,.07);color:#20d9ff;font-size:8px;font-weight:900}.activityAlert.high,.activityAlert.critical{color:#ff667e;background:rgba(255,82,110,.08)}.activityAlert.medium{color:#ffb14a;background:rgba(255,177,74,.08)}.activityList b{display:block;font-size:8px}.activityList small{display:block;font-size:7px;color:#607f93;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:430px}.activityList em{font-style:normal;font-size:7px;color:#587589}.cockpitEmpty{padding:28px 12px;text-align:center;color:#5f7d91;font-size:8px}@keyframes wsPulse{0%,100%{box-shadow:0 0 0 0 rgba(62,228,155,.5)}50%{box-shadow:0 0 0 6px rgba(62,228,155,0)}}@keyframes wsDraw{to{stroke-dashoffset:0}}@keyframes wsBar{from{width:0}}@keyframes wsPop{from{opacity:0;transform:scale(.86)}to{opacity:1;transform:scale(1)}}@keyframes wsSpin{to{transform:rotate(360deg)}}
      @media(max-width:1180px){.cockpitKpis{grid-template-columns:repeat(3,1fr)}.cockpitTripleGrid{grid-template-columns:1fr 1fr}.cockpitTripleGrid>article:last-child{grid-column:1/-1}}
      @media(max-width:800px){.cockpitTitle,.cockpitWebsite{align-items:flex-start;flex-direction:column}.heroActionsMini{margin-left:0}.cockpitScan{grid-template-columns:1fr}.cockpitScan>small{grid-column:auto}.cockpitKpis{grid-template-columns:1fr 1fr}.cockpitMainGrid,.cockpitMainGrid.lower,.cockpitBottomGrid,.cockpitTripleGrid{grid-template-columns:1fr}.cockpitTripleGrid>article:last-child{grid-column:auto}.scoreBody{grid-template-columns:1fr;justify-items:center}.scoreMeta{width:100%}}
    `}</style>
  </div>;
}
