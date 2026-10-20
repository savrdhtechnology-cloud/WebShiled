"use client";
import { apiPath } from "@/lib/base-path";

import { FormEvent, useEffect, useRef, useState } from "react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type ScanFinding = { severity: Severity; category: string; title: string; detail: string; impact: string; fix: string };
export type ScanResult = {
  requestedUrl: string;
  finalUrl: string;
  hostname: string;
  status: number;
  statusText: string;
  responseMs: number;
  https: boolean;
  redirectedToHttps: boolean;
  redirectChain: string[];
  securityScore: number;
  grade: string;
  overallRisk: Severity;
  findingCounts: Record<Severity, number>;
  findings: ScanFinding[];
  headers: { key: string; label: string; present: boolean; value: string | null; fix: string }[];
  server: string | null;
  poweredBy: string | null;
  cors: string | null;
  cookies: { observed: number; missingSecure: number; missingHttpOnly: number; missingSameSite: number };
  dns: { resolved: boolean; addresses: { address: string; family: number }[] };
  technologies: { signal: string; value: string }[];
  resources: { securityTxt: { exists: boolean; status: number; finalUrl: string | null }; robotsTxt: { exists: boolean; status: number; finalUrl: string | null } };
  emailSecurity?: {spf:{present:boolean;record:string|null};dmarc:{present:boolean;record:string|null}};
  mixedContent?:boolean;
  httpProbe?:{status:number;redirectsToHttps:boolean;finalUrl:string|null};
  capabilities: Record<string, string>;
  scannedAt: string;
  mode: string;
  note: string;
};

function tone(severity: string) {
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "safe";
}

function capabilityLabel(key: string) {
  return ({
    visitorMonitoring: "Real-Time Visitor Monitoring",
    threatDetection: "Threat Detection",
    websiteProtection: "Website Protection",
    botDetection: "Bot & Malicious Traffic Detection",
    analytics: "Visitor & Security Analytics",
    alerts: "Attack & Threat Alerts",
    easyIntegration: "Website Integration",
    reports: "Security Reports & Insights"
  } as Record<string, string>)[key] || key;
}

export function WebsiteScanner({publicScan=false,initialUrl="",autoScan=false,initialScan}:{publicScan?:boolean;initialUrl?:string;autoScan?:boolean;initialScan?:ScanResult}) {
  const [url, setUrl] = useState(initialUrl||initialScan?.requestedUrl||"");
  const [scan, setScan] = useState<ScanResult | null>(initialScan||null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [tab,setTab]=useState('findings');
  const [severity,setSeverity]=useState('ALL');
  const formRef=useRef<HTMLFormElement>(null);
  const resultsRef=useRef<HTMLDivElement>(null);
  const started=useRef(false);
  useEffect(()=>{if(autoScan&&initialUrl.trim()&&!started.current){started.current=true;formRef.current?.requestSubmit()}},[autoScan,initialUrl]);
  useEffect(()=>{if(scan){resultsRef.current?.scrollIntoView({block:'start',behavior:'auto'});resultsRef.current?.focus({preventScroll:true})}},[scan]);
  function download(){if(!scan)return;const blob=new Blob([JSON.stringify(scan,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`webshield-${scan.hostname}-scan.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setScan(null);
    setTab("findings");setSeverity("ALL");
    setLoading(true);
    try {
      const response = await fetch(apiPath(publicScan?"/api/public-scan":"/api/scan"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await response.json();
      if (!response.ok || !data?.ok) throw new Error(typeof data?.error==="string"?data.error:data?.error?.message||"Scan failed.");
      const result = data.scan as ScanResult;
      if(!result?.hostname||!Array.isArray(result.findings)||!Array.isArray(result.headers)||typeof result.securityScore!=="number")throw new Error("The scanner returned an incomplete report. Please try again.");
      setScan(result);
      try {
        window.localStorage.setItem("webshield:last-scan", JSON.stringify(result));
        window.dispatchEvent(new Event("webshield:scan-updated"));
      } catch { /* local storage can be disabled */ }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  const order=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const findings=scan?.findings.filter(f=>severity==='ALL'||f.severity===severity).sort((a,b)=>order.indexOf(a.severity)-order.indexOf(b.severity))||[];
  return <article className="websiteScanner" aria-busy={loading}>
    <header className="scannerHeading"><div><span className="scannerEyebrow">WEBSHIELD · LIVE PASSIVE SCAN</span><h2>Website Security Scan</h2><p>Observed security posture, evidence and recommended fixes.</p></div><span className="scannerLive">● Live check</span></header>
    <div className="scannerBody">
      <form ref={formRef} onSubmit={submit} className="scannerForm"><label htmlFor="scanner-url">Website URL</label><div><input id="scanner-url" aria-label="Website URL" value={url} onChange={e=>setUrl(e.target.value)} placeholder="example.com or https://example.com" required disabled={loading}/><button type="submit" disabled={loading}>{loading?'Scanning…':'Scan Website'}</button></div></form>
      {loading&&<div className="scannerProgress" role="status"><i/><div><b>Checking website security…</b><p>Reading the response, HTTPS redirects, security headers and public configuration.</p></div></div>}
      {error&&<div className="scannerError" role="alert"><b>Scan could not be completed</b><p>{error}</p><span>Check the domain and try again. Previous results are not shown as a successful scan.</span></div>}
      {scan&&<div className="scannerResults" ref={resultsRef} tabIndex={-1}>
        <div className="scannerReportHead"><div><span className="scannerEyebrow">SCAN COMPLETE</span><h3>{scan.hostname}</h3><a href={scan.finalUrl} target="_blank" rel="noopener noreferrer">{scan.finalUrl}</a><p>{new Date(scan.scannedAt).toLocaleString()} · HTTP {scan.status} {scan.statusText}</p></div><button type="button" onClick={download}>Download report</button></div>
        {scan.status>=400&&<div className="scannerError" role="status"><b>Target returned HTTP {scan.status}</b><p>These observations describe the returned error or access-control response. They may not represent the normal website response.</p></div>}<div className="scannerMetrics"><div><span>Security score</span><strong>{scan.securityScore}<small>/100</small></strong><p>Grade {scan.grade}</p></div><div><span>Overall risk</span><strong className={'severity-'+scan.overallRisk.toLowerCase()}>{scan.overallRisk}</strong><p>{scan.findings.length} findings observed</p></div><div><span>HTTPS</span><strong>{scan.https?'Enabled':'Not enabled'}</strong><p>{scan.redirectedToHttps?'HTTP → HTTPS enforced':'HTTP redirect not confirmed'}</p></div><div><span>Response time</span><strong>{scan.responseMs}<small> ms</small></strong><p>Live HTTP response</p></div></div>
        <div className="scannerFilters" aria-label="Filter findings by severity">{['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(level=><button type="button" aria-pressed={severity===level} key={level} onClick={()=>{setSeverity(level);setTab('findings')}}><i className={'severityDot '+level.toLowerCase()}/>{level==='ALL'?'All findings':level}<b>{level==='ALL'?scan.findings.length:scan.findingCounts[level as Severity]||0}</b></button>)}</div>
        <div className="scannerTabs" role="tablist" aria-label="Scan report sections">{[['findings','Issues & fixes'],['headers','Security headers'],['technical','Technical details'],['coverage','Protection coverage']].map(([key,label])=><button role="tab" id={'scan-tab-'+key} aria-controls={'scan-panel-'+key} aria-selected={tab===key} type="button" key={key} onClick={()=>setTab(key)}>{label}</button>)}</div>
        <section className="scannerTabPanel" role="tabpanel" id={'scan-panel-'+tab} aria-labelledby={'scan-tab-'+tab}>
        {tab==='findings'&&<><div className="scannerSectionIntro"><h3>Priority security findings</h3><p>{severity==='ALL'?'All observed findings, including informational checks.':`Showing ${severity.toLowerCase()} findings.`} Each finding includes evidence, impact and a suggested fix.</p></div>{findings.length?findings.map((f,i)=><article className="scannerFinding" key={f.title+i}><header><span className={'scannerSeverity '+f.severity.toLowerCase()}>{f.severity}</span><div><h4>{f.title}</h4><small>{f.category}</small></div></header><div className="scannerFindingDetails"><div><b>Observed evidence</b><p>{f.detail}</p></div><div><b>Why it matters</b><p>{f.impact}</p></div><div className="scannerFix"><b>Recommended fix</b><p>{f.fix}</p></div></div></article>):<div className="scannerEmpty">{scan.findings.length?'No findings match this severity. Select All findings to see the full report.':'No material passive posture findings were detected. This does not guarantee that the website has no vulnerabilities.'}</div>}</>}
        {tab==='headers'&&<><h3>Observed security headers</h3><p>Presence on the final HTTP response. Presence alone does not prove that a policy is configured safely.</p>{scan.headers.map(h=><details className="scannerControl" key={h.key}><summary><strong>{h.label}</strong><span className={'scannerSeverity '+(h.present?'safe':'medium')}>{h.present?'PRESENT':'MISSING'}</span></summary><code>{h.key}</code>{h.value&&<pre>{h.value}</pre>}<p>{h.present?'Review the observed value against your application requirements.':h.fix}</p></details>)}</>}
        {tab==='technical'&&<><h3>Technical posture</h3><dl className="scannerTechnical">{[['Requested URL',scan.requestedUrl],['Final URL',scan.finalUrl],['HTTP status',`${scan.status} ${scan.statusText}`],['DNS resolution',scan.dns.resolved?'Resolved':'Not resolved'],['Public addresses',scan.dns.addresses.map(a=>a.address).join(', ')||'Not observed'],['Server',scan.server||'Not exposed'],['Powered by',scan.poweredBy||'Not exposed'],['CORS',scan.cors||'Not exposed'],['Cookies observed',String(scan.cookies.observed)],['Cookies without Secure',String(scan.cookies.missingSecure)],['Cookies without HttpOnly',String(scan.cookies.missingHttpOnly)],['Cookies without SameSite',String(scan.cookies.missingSameSite)],['security.txt',scan.resources.securityTxt.exists?'Found':`Not found (HTTP ${scan.resources.securityTxt.status||'unavailable'})`],['robots.txt',scan.resources.robotsTxt.exists?'Found':`Not found (HTTP ${scan.resources.robotsTxt.status||'unavailable'})`],['SPF record',scan.emailSecurity?.spf.record||'Not detected'],['DMARC record',scan.emailSecurity?.dmarc.record||'Not detected'],['Mixed HTTP resource references',scan.mixedContent?'Observed':'Not observed in returned HTML'],['HTTP redirect probe',scan.httpProbe?.status?`HTTP ${scan.httpProbe.status} · ${scan.httpProbe.finalUrl||''}`:'Not confirmed']].map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl><h3>Redirect chain</h3><ol className="scannerRedirects">{scan.redirectChain.map((u,i)=><li key={i}>{u}</li>)}</ol><h3>Observed technology signals</h3>{scan.technologies.length?<dl className="scannerTechnical">{scan.technologies.map((t,i)=><div key={i}><dt>{t.signal}</dt><dd>{t.value}</dd></div>)}</dl>:<p>No technology headers were exposed.</p>}</>}
        {tab==='coverage'&&<><h3>Protection coverage</h3><p>A passive scan checks public response posture. Continuous monitoring and protection need a connected collector or traffic provider.</p><dl className="scannerTechnical">{Object.entries(scan.capabilities).map(([k,v])=><div key={k}><dt>{capabilityLabel(k)}</dt><dd><span className={'scannerSeverity '+(v.includes('REQUIRES')?'medium':'safe')}>{v.replaceAll('_',' ')}</span></dd></div>)}</dl><a className="scannerProtect" href="/app/websites">Connect this website for monitoring →</a></>}
        </section><p className="scannerNote">{scan.note}</p>
      </div>}
      {!scan&&!loading&&!error&&<p className="scannerNote">Enter a public website URL to inspect its HTTPS, response headers and publicly exposed configuration.</p>}
    </div>
  </article>;
}
