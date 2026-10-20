'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { apiPath } from '@/lib/base-path';
import { Icon } from './icons';
import { WebsiteScanner, type ScanResult } from './website-scanner';

type Site = {
  id: string;
  domain: string;
  status?: string | null;
  verified_at?: string | null;
  ssl_status?: string | null;
  integration_status?: string | null;
  last_event_at?: string | null;
  created_at?: string | null;
};

type Integration = Site & {
  collector_key?: string | null;
  collector_enabled?: boolean | null;
};

type DashboardResponse = {
  metrics?: Record<string, number>;
  websitesData?: Site[];
};

function Badge({ children }: { children: React.ReactNode }) {
  return <span className={'refBadge ' + String(children).toLowerCase().replaceAll(' ', '-')}>{children}</span>;
}

function Bars() {
  return <span className="refBars">{[12,20,15,28,18,34,24,42].map((v,i)=><i key={i} style={{height:v}} />)}</span>;
}

function Ring({ value }: { value: number }) {
  return <div className="refRing" style={{background:`conic-gradient(#00edb1 ${Math.max(0,Math.min(100,value))*3.6}deg,#0b2736 0)`}}>
    <div><strong>{value}</strong><span>/ 100</span></div>
  </div>;
}

function Panel({ title, icon='shield', note, action, children }: { title:string; icon?:string; note?:string; action?:React.ReactNode; children:React.ReactNode }) {
  return <section className="refPanel" id={title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/-$/,'')}>
    <header><Icon name={icon} size={25}/><div><h2>{title}</h2>{note&&<p>{note}</p>}</div>{action}</header>
    {children}
  </section>;
}

export function ConnectedWebsites() {
  const [sites,setSites]=useState<Site[]>([]);
  const [dashboard,setDashboard]=useState<DashboardResponse|null>(null);
  const [lastScan,setLastScan]=useState<ScanResult|null>(null);
  const [query,setQuery]=useState('');
  const [pendingOnly,setPendingOnly]=useState(false);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');
  const [modal,setModal]=useState<'scan'|'add'|'manage'|''>('');
  const [domain,setDomain]=useState('');
  const [selected,setSelected]=useState<Site|null>(null);
  const [integration,setIntegration]=useState<Integration|null>(null);
  const [busy,setBusy]=useState(false);
  const [copied,setCopied]=useState(false);

  const load=useCallback(async()=>{
    setLoading(true); setError('');
    try {
      const [siteResponse,dashboardResponse]=await Promise.all([
        fetch(apiPath('/api/websites'),{cache:'no-store'}),
        fetch(apiPath('/api/dashboard'),{cache:'no-store'})
      ]);
      const [siteBody,dashboardBody]=await Promise.all([siteResponse.json(),dashboardResponse.json()]);
      if(!siteResponse.ok||!siteBody.ok) throw new Error(siteBody?.error?.message||'Unable to load websites.');
      if(!dashboardResponse.ok||!dashboardBody.ok) throw new Error(dashboardBody?.error?.message||'Unable to load website metrics.');
      setSites(Array.isArray(siteBody.data)?siteBody.data:[]);
      setDashboard(dashboardBody.data||{});
    } catch(e) {
      setError(e instanceof Error?e.message:'Unable to load websites.');
    } finally {
      setLoading(false);
    }
  },[]);

  useEffect(()=>{load()},[load]);
  useEffect(()=>{
    const read=()=>{try{const raw=localStorage.getItem('webshield:last-scan');if(raw){const scan=JSON.parse(raw);if(scan?.hostname&&Array.isArray(scan.findings))setLastScan(scan)}}catch{}};
    read(); window.addEventListener('webshield:scan-updated',read);
    return()=>window.removeEventListener('webshield:scan-updated',read);
  },[]);

  const filtered=useMemo(()=>sites.filter(site=>
    site.domain.toLowerCase().includes(query.toLowerCase())&&
    (!pendingOnly||!site.verified_at||site.integration_status!=='COLLECTOR_CONNECTED')
  ),[sites,query,pendingOnly]);

  const protectedCount=sites.filter(s=>Boolean(s.verified_at)&&s.integration_status==='COLLECTOR_CONNECTED').length;
  const pendingCount=sites.filter(s=>!s.verified_at).length;
  const latestScore=lastScan?.securityScore ?? 0;
  const scoreAvailable=Boolean(lastScan);
  const findings=lastScan?.findingCounts||{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};

  async function addWebsite(e:FormEvent){
    e.preventDefault(); if(!domain.trim()) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const response=await fetch(apiPath('/api/websites'),{
        method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({domain})
      });
      const body=await response.json();
      if(!response.ok||!body.ok) throw new Error(body?.error?.message||'Could not add website.');
      setDomain(''); setModal(''); setNotice(body.meta?.reused?'Website already exists in this workspace.':'Website added to WebShield.');
      await load();
    } catch(e) { setError(e instanceof Error?e.message:'Could not add website.'); }
    finally { setBusy(false); }
  }

  function runScan(e:FormEvent){
    e.preventDefault(); if(!domain.trim()) return;
    setError(''); setModal('scan');
  }

  async function manage(site:Site){
    setSelected(site); setIntegration(null); setCopied(false); setError(''); setModal('manage'); setBusy(true);
    try {
      const response=await fetch(apiPath('/api/websites/integration')+'?id='+encodeURIComponent(site.id),{cache:'no-store'});
      const body=await response.json();
      if(!response.ok||!body.ok) throw new Error(body?.error?.message||'Could not load website integration.');
      setIntegration(body.data);
    } catch(e) { setError(e instanceof Error?e.message:'Could not load website integration.'); }
    finally { setBusy(false); }
  }

  async function integrationAction(action:'enable'|'disable'|'verify'){
    if(!selected) return; setBusy(true); setError('');
    try {
      const response=await fetch(apiPath('/api/websites/integration'),{
        method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:selected.id,action})
      });
      const body=await response.json();
      if(!response.ok||!body.ok) throw new Error(body?.error?.message||'Could not update integration.');
      setIntegration(body.data); setNotice('Website integration updated.'); await load();
    } catch(e) { setError(e instanceof Error?e.message:'Could not update integration.'); }
    finally { setBusy(false); }
  }

  async function removeWebsite(){
    if(!selected||!window.confirm(`Remove ${selected.domain} from this WebShield workspace?`)) return;
    setBusy(true); setError('');
    try {
      const response=await fetch(apiPath('/api/websites')+'?id='+encodeURIComponent(selected.id),{method:'DELETE'});
      const body=await response.json();
      if(!response.ok||!body.ok) throw new Error(body?.error?.message||'Could not remove website.');
      setModal(''); setSelected(null); setIntegration(null); setNotice(selected.domain+' removed.'); await load();
    } catch(e) { setError(e instanceof Error?e.message:'Could not remove website.'); }
    finally { setBusy(false); }
  }

  const snippet=integration?.collector_key
    ? `<script async src="${typeof window!=='undefined'?window.location.origin:''}/webshield/webshield.js" data-site-key="${integration.collector_key}"></script>`
    : '';

  async function copySnippet(){
    if(!snippet) return;
    await navigator.clipboard.writeText(snippet); setCopied(true); setTimeout(()=>setCopied(false),1500);
  }

  return <div className="connectedOverview">
    {notice&&<div className="refNotice" role="status">{notice}<button onClick={()=>setNotice('')} aria-label="Dismiss">×</button></div>}
    {error&&!modal&&<div className="moduleError" role="alert"><b>{error}</b><button onClick={load}>Retry</button></div>}

    <form className="refScan" onSubmit={runScan}>
      <Icon name="key"/>
      <input aria-label="Website to scan" placeholder="https://example.com or example.com" value={domain} onChange={e=>setDomain(e.target.value)} required/>
      <button className="refPrimary" disabled={busy}>⌕　Scan Website</button>
      <button type="button" onClick={()=>{setError('');setModal('add')}}>＋　Add Website</button>
    </form>

    <div className="refMetrics">
      <div className="refMetric tone0"><div className="refMetricIcon"><Icon name="globe" size={29}/></div><div><span>Connected Websites</span><strong>{sites.length}</strong><p>Websites in this workspace</p></div><Bars/></div>
      <div className="refMetric tone1"><div className="refMetricIcon"><Icon name="shield" size={29}/></div><div><span>Active Protection</span><strong>{protectedCount}</strong><p>Verified collector connections</p></div><Bars/></div>
      <div className="refMetric tone2"><div className="refMetricIcon"><Icon name="lock" size={29}/></div><div><span>Verification Pending</span><strong>{pendingCount}</strong><p>Awaiting ownership verification</p></div><Bars/></div>
      <div className="refMetric tone3"><div className="refMetricIcon"><Icon name="settings" size={29}/></div><div><span>Latest Security Score</span><strong>{scoreAvailable?latestScore:'—'}{scoreAvailable&&<small> / 100</small>}</strong><p>{scoreAvailable?'Latest completed passive scan':'Run a scan to calculate score'}</p></div><Bars/></div>
    </div>

    <div className="refColumns">
      <div className="refStack">
        <Panel title="Connected Websites" icon="globe" note="Manage your websites, integration status, verification, and recent activity." action={<button onClick={()=>setPendingOnly(v=>!v)}>{pendingOnly?'Show all':'Filter pending'}</button>}>
          {loading?<p>Loading websites…</p>:filtered.length?<div className="refTable"><table>
            <thead><tr>{['Domain','Status','SSL','Integration','Verification','Last activity',''].map(x=><th key={x}>{x}</th>)}</tr></thead>
            <tbody>{filtered.map((site,i)=><tr key={site.id}>
              <td><div className="refDomain"><b className={'refFavicon f'+(i%4)}>{site.domain.slice(0,2).toUpperCase()}</b><div><strong>{site.domain}</strong><small>Workspace website</small></div></div></td>
              <td><Badge>{site.status||'PENDING'}</Badge></td>
              <td className={site.ssl_status==='VALID'?'refGreen':''}>{site.ssl_status||'UNKNOWN'}</td>
              <td><Badge>{site.integration_status||'NOT CONNECTED'}</Badge></td>
              <td><Badge>{site.verified_at?'Verified':'Pending'}</Badge></td>
              <td>{site.last_event_at?new Date(site.last_event_at).toLocaleString():'No event yet'}</td>
              <td><button aria-label={'Manage '+site.domain} onClick={()=>manage(site)}>•••</button></td>
            </tr>)}</tbody>
          </table></div>:<p>No websites found. Add your first website above.</p>}
        </Panel>

        <div className="refEqual">
          <Panel title="Recent Scans" icon="chart" note="Latest completed passive security scan from this browser session.">
            {lastScan?<button className="refScanRow" onClick={()=>{setDomain(lastScan.requestedUrl);setModal('scan')}}><span>{lastScan.hostname}</span><small>{new Date(lastScan.scannedAt).toLocaleString()}</small><b>{lastScan.securityScore}</b><Badge>{lastScan.overallRisk}</Badge></button>:<p>No completed scan yet. Run a website scan above.</p>}
          </Panel>
          <Panel title="Top Issues" icon="threat" note="Observed findings from the latest completed passive scan.">
            {lastScan?.findings.length?lastScan.findings.slice(0,5).map(f=><div className="refScanRow" key={f.title}><span>{f.title}</span><Badge>{f.severity}</Badge></div>):<p>No scan findings available yet.</p>}
          </Panel>
        </div>
      </div>

      <div className="refStack">
        <Panel title="Scan Findings" icon="report" note={lastScan?'Latest live scan: '+lastScan.hostname:'Run a passive scan to populate findings.'} action={lastScan?<button onClick={()=>{setDomain(lastScan.requestedUrl);setModal('scan')}}>View Details</button>:undefined}>
          {lastScan?<div className="refRisk"><Ring value={lastScan.securityScore}/><div>{['Critical Issues','High Risk','Medium Risk','Low Risk','Info'].map((label,i)=><p key={label}><span className={'refDot dot'+i}/>{label}<b>{findings[(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const)[i]]||0}</b></p>)}</div></div>:<p>No scan data yet.</p>}
        </Panel>

        <Panel title="Protection Activation" icon="shield" note="Complete each verified step to activate available monitoring and protection.">
          {[
            ['Website Added',sites.length>0,'Website exists in this workspace'],
            ['Ownership Verified',sites.some(s=>Boolean(s.verified_at)),'Domain ownership confirmed'],
            ['Collector Connected',sites.some(s=>s.integration_status==='COLLECTOR_CONNECTED'),'Security collector is receiving data'],
            ['WAF Connected',false,'Traffic-path/WAF provider integration required'],
            ['Auto Protection',false,'Requires supported enforcement provider']
          ].map(([label,done,note],i)=><div className="refStep" key={String(label)}>
            <b className={done?'done':''}>{done?'✓':i+1}</b>
            <div>{String(label)}<small>{String(note)}</small></div>
            <span>{done?'Completed':'Pending'}</span>
          </div>)}
        </Panel>
      </div>
    </div>

    {modal&&<div className="refModalBackdrop" onClick={()=>setModal('')}>
      <section className={'refModal '+(modal==='scan'?'refScanModal':'')} role="dialog" aria-modal="true" onClick={e=>e.stopPropagation()}>
        <button className="refModalClose" aria-label="Close dialog" onClick={()=>setModal('')}>×</button>
        {modal==='scan'&&<WebsiteScanner initialUrl={domain} autoScan={Boolean(domain.trim())}/>}
        {modal==='add'&&<><Icon name="globe" size={36}/><h2>Add Website</h2><form onSubmit={addWebsite}><label>Website domain<input autoFocus value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" required/></label>{error&&<p className="moduleError">{error}</p>}<button className="refPrimary" disabled={busy}>{busy?'Adding…':'Add Website'}</button></form></>}
        {modal==='manage'&&<><Icon name="shield" size={36}/><h2>{selected?.domain}</h2>{busy&&!integration?<p>Loading integration…</p>:integration?<div className="moduleDetail">
          <div><dt>Status</dt><dd>{integration.status||'PENDING'}</dd></div>
          <div><dt>Verification</dt><dd>{integration.verified_at?'Verified':'Pending'}</dd></div>
          <div><dt>Collector</dt><dd>{integration.collector_enabled?'Enabled':'Disabled'}</dd></div>
          <div><dt>Integration</dt><dd>{integration.integration_status||'NOT_CONNECTED'}</dd></div>
          <div><dt>Last event</dt><dd>{integration.last_event_at?new Date(integration.last_event_at).toLocaleString():'Not received yet'}</dd></div>
        </div>:null}
        {snippet&&<><label>Universal integration code<textarea readOnly value={snippet} onFocus={e=>e.currentTarget.select()}/></label><button onClick={copySnippet}>{copied?'Copied ✓':'Copy Code'}</button></>}
        {error&&<p className="moduleError">{error}</p>}
        <div className="refActions">
          <button className="refPrimary" disabled={busy} onClick={()=>integrationAction('enable')}>Enable Collector</button>
          <button disabled={busy} onClick={()=>integrationAction('verify')}>Check Connection</button>
          <button disabled={busy} onClick={()=>integrationAction('disable')}>Disable</button>
          <button disabled={busy} onClick={removeWebsite}>Remove Website</button>
        </div></>}
      </section>
    </div>}
  </div>;
}
