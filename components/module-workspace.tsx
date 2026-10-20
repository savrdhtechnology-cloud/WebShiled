'use client';
import { apiPath } from "@/lib/base-path";
import Link from 'next/link';
import {bucketSessions,rowsToCsv} from '@/lib/telemetry';
import {useCallback,useEffect,useMemo,useRef,useState,type FormEvent} from 'react';
import {ActivityGraph,VisitorMap,sampleLocations,type TrafficPoint} from './traffic-visuals';
import {DatabaseSecurity} from './database-security';
import {AppearanceStudioPage} from './appearance-studio';
import {Icon} from './icons';

type Row=Record<string,unknown>;
const sampleThreats:Row[]=[{id:'DEMO-01',type:'Bot Activity',severity:'HIGH',source_ip:'192.0.2.10',target_url:'/login',risk_score:82,status:'OPEN'},{id:'DEMO-02',type:'Suspicious Request',severity:'MEDIUM',source_ip:'192.0.2.11',target_url:'/api',risk_score:61,status:'OPEN'},{id:'DEMO-03',type:'Login Probe',severity:'MEDIUM',source_ip:'192.0.2.12',target_url:'/admin',risk_score:56,status:'OPEN'}];
const sampleAlerts:Row[]=[{id:'ALERT-01',title:'Website verification pending',severity:'MEDIUM',message:'Verify demo-app.vercel.app before activating protection.',acknowledged_at:null}];
const sampleTickets:Row[]=[{id:'TICKET-01',subject:'Collector installation help',priority:'MEDIUM',status:'OPEN',description:'How do I connect my website?'}];
const text=(value:unknown)=>value==null?'—':typeof value==='object'?JSON.stringify(value):String(value);
export function exportCsv(rows:Row[],name:string){const csv=rowsToCsv(rows);const url=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=name+'.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}

export function ModuleWorkspace({page,connected=false}:{page:string;connected?:boolean}){
 const resource=({'threat-center':'threats','security-events':'threats','alerts':'alerts','support':'support','support-tickets':'support','firewall':'firewall','reports':'reports','analytics':'analytics','plans':'billing','settings':'workspace','system-settings':'workspace'} as Record<string,string>)[page];
 const [rows,setRows]=useState<Row[]>([]),[metrics,setMetrics]=useState<Row>({}),[error,setError]=useState(''),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[query,setQuery]=useState(''),[severity,setSeverity]=useState('All'),[selected,setSelected]=useState<Row|null>(null),[notice,setNotice]=useState(''),[subject,setSubject]=useState(''),[description,setDescription]=useState(''),[priority,setPriority]=useState('MEDIUM'),[ruleAction,setRuleAction]=useState('BLOCK');
 const loadVersion=useRef(0);
 const load=useCallback(async()=>{if(!resource)return;const version=++loadVersion.current;setError('');setLoading(true);try{if(!connected){setRows(resource==='threats'?sampleThreats:resource==='alerts'?sampleAlerts:resource==='support'?sampleTickets:resource==='firewall'?[{id:'RULE-01',name:'Review high-risk traffic',action:'BLOCK',enabled:true,provider_rule_id:null}]:[]);setMetrics({visitors:248,sessions:312,threats:3,blockedRequests:24});return}const response=await fetch(apiPath('/api/'+resource),{cache:'no-store'});const body=await response.json();if(version!==loadVersion.current)return;if(!response.ok||!body.ok)throw Error(body.error?.message||'Unable to load workspace data.');setRows(Array.isArray(body.data)?body.data:Array.isArray(body.data?.rules)?body.data.rules:[]);setMetrics(body.data&&!Array.isArray(body.data)?body.data:{});}catch(e){if(version===loadVersion.current)setError(e instanceof Error?e.message:'Request failed')}finally{if(version===loadVersion.current)setLoading(false)}},[resource,connected]);
 useEffect(()=>{load();return()=>{loadVersion.current++}},[load]);
 const filtered=useMemo(()=>rows.filter(row=>(severity==='All'||String(row.severity||row.status)===severity)&&JSON.stringify(row).toLowerCase().includes(query.toLowerCase())),[rows,severity,query]);
 async function write(body:Row,method='POST'){setBusy(true);setError('');try{const r=await fetch(apiPath('/api/'+resource),{method,headers:{'content-type':'application/json'},body:JSON.stringify(body)});const b=await r.json();if(!r.ok||!b.ok)throw Error(b.error?.message||'Could not save changes.');await load();return true}catch(e){setError(e instanceof Error?e.message:'Request failed');return false}finally{setBusy(false)}}
 async function acknowledge(row:Row){if(connected){if(!await write({id:row.id}))return}else setRows(current=>current.map(r=>r.id===row.id?{...r,acknowledged_at:new Date().toISOString()}:r));setSelected(null);setNotice(connected?'Alert acknowledged in Supabase.':'Alert acknowledged in this preview session.')}
 async function resolve(row:Row){if(connected){if(!await write({id:row.id,status:'RESOLVED'},'PATCH'))return}else setRows(current=>current.map(r=>r.id===row.id?{...r,status:'RESOLVED'}:r));setSelected(null);setNotice(connected?'Threat status updated.':'Threat resolved in this preview session.')}
 async function create(e:FormEvent){e.preventDefault();if(connected){if(!await write(resource==='support'?{subject,description,priority}:{name:subject,action:ruleAction,conditions:[{field:'risk_score',operator:'greater_than',value:80}]}))return}else setRows(current=>[{id:'LOCAL-'+Date.now(),...(resource==='support'?{subject,description,priority,status:'OPEN'}:{name:subject,action:ruleAction,enabled:true,provider_rule_id:null})},...current]);setSubject('');setDescription('');setNotice(resource==='support'?'Support ticket created.':'Rule saved. Enforcement requires a connected traffic provider.')}
 if(page==='database-security'||page==='fix-center')return <div className="connectedModule"><DatabaseSecurity mode={page==='fix-center'?'fixes':'security'}/></div>;
 if(page==='appearance')return <AppearanceStudioPage/>;
 if(page==='settings'||page==='system-settings')return <div className="workspaceModule"><section className="refPanel"><h2>Workspace connection</h2><p>Database: szvxrgbshmmsvujkusdm.supabase.co</p><p>{connected?'Authenticated workspace · Row Level Security enforced':'Design preview · Sign in to access workspace data'}</p>{loading?<p>Loading account…</p>:error?<p role="alert">{error}</p>:connected?<dl className="moduleDetail">{Object.entries(metrics).map(([k,v])=><div key={k}><dt>{k}</dt><dd>{text(v)}</dd></div>)}</dl>:<Link href="/login?next=/app/dashboard" className="refPrimary">Sign in to workspace</Link>}</section><AppearanceStudioPage/></div>;
 return <div className="workspaceModule"><div className="moduleToolbar"><label className="refSearch"><input aria-label="Search records" placeholder="Search records…" value={query} onChange={e=>setQuery(e.target.value)}/></label>{(resource==='threats'||resource==='alerts')&&<select aria-label="Filter severity" value={severity} onChange={e=>setSeverity(e.target.value)}>{['All','CRITICAL','HIGH','MEDIUM','LOW'].map(s=><option key={s}>{s}</option>)}</select>}<button disabled={loading} onClick={load}>Refresh</button><button disabled={loading||!!error||(!filtered.length&&!Object.keys(metrics).length)} onClick={()=>exportCsv(filtered.length?filtered:[metrics],`webshield-${page}`)}>Export CSV</button></div>{notice&&<p className="refNotice" role="status">{notice}</p>}{error&&<div className="moduleError" role="alert"><b>{error}</b><p>Data could not be loaded. No sample records are substituted for connected data.</p><button onClick={load}>Retry</button></div>}{loading&&<p role="status">Loading workspace records…</p>}
 {(resource==='support'||resource==='firewall')&&<form className="refPanel moduleForm" onSubmit={create}><h2>{resource==='support'?'Create support ticket':'Create security rule'}</h2><label>{resource==='support'?'Subject':'Rule name'}<input value={subject} onChange={e=>setSubject(e.target.value)} required maxLength={160}/></label>{resource==='support'?<><label>Description<textarea value={description} onChange={e=>setDescription(e.target.value)} required maxLength={4000}/></label><label>Priority<select value={priority} onChange={e=>setPriority(e.target.value)}><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select></label></>:<><label>Action<select value={ruleAction} onChange={e=>setRuleAction(e.target.value)}>{['BLOCK','ALLOW','CHALLENGE','RATE_LIMIT'].map(s=><option key={s}>{s}</option>)}</select></label><p>Matches requests with risk score greater than 80. Saved rules require a traffic provider for enforcement.</p></>}<button className="refPrimary" disabled={busy}>{busy?'Saving…':resource==='support'?'Create ticket':'Save rule'}</button></form>}
 {(resource==='analytics'||resource==='reports')&&!loading&&!error&&Object.keys(metrics).length>0&&<><div className="refMetrics">{Object.entries(metrics).filter(([,v])=>typeof v==='number').map(([k,v])=><button className="refMetric moduleMetric" key={k} onClick={()=>setSelected({metric:k,value:v,source:connected?'Supabase aggregate':'Sample data'})}><span>{k.replace(/([A-Z])/g,' $1')}</span><strong>{text(v)}</strong><small>View details →</small></button>)}</div><section className="refPanel"><h2>{resource==='reports'?'Security report':'Traffic analytics'}</h2><p>{connected?'Export the current backend summary as CSV. Explore collected traffic for historical activity.':'Preview data. Open the connected workspace for your real reports.'}</p>{connected?<Link className="refPrimary" href="/app/live-traffic">Explore collected traffic</Link>:<ActivityGraph sample/>}<button onClick={()=>exportCsv([metrics],`webshield-${page}-summary`)}>Download summary CSV</button></section></>}
 {!loading&&!error&&['threats','alerts','support','firewall'].includes(resource)&&<section className="refPanel"><header><div><h2>{page==='threat-center'?'Threat events':page==='alerts'?'Security alerts':page==='support'?'Support tickets':'Firewall rules'}</h2><p>{filtered.length} records · {connected?'Supabase workspace':'interactive sample data'}</p></div></header>{filtered.length?<div className="refTable"><table><thead><tr>{Object.keys(filtered[0]).filter(k=>!['metadata','description','message','conditions'].includes(k)).slice(0,7).map(k=><th key={k}>{k.replaceAll('_',' ')}</th>)}<th>Actions</th></tr></thead><tbody>{filtered.map(row=><tr key={text(row.id)}>{Object.keys(filtered[0]).filter(k=>!['metadata','description','message','conditions'].includes(k)).slice(0,7).map(k=><td key={k}>{text(row[k])}</td>)}<td><button onClick={()=>setSelected(row)}>View details</button></td></tr>)}</tbody></table></div>:<p>No matching records. {connected?'New records appear after your website collector is connected.':'Try a different filter.'}</p>}</section>}
 {resource==='billing'&&!loading&&!error&&<section className="refPanel"><header><div><h2>Plans & Billing</h2><p>Current subscription and plan details for this workspace.</p></div></header><dl className="moduleDetail">{Object.entries(metrics).map(([k,v])=><div key={k}><dt>{k.replaceAll('_',' ')}</dt><dd>{text(v)}</dd></div>)}</dl></section>}
 {selected&&<section className="refPanel moduleSelected" aria-label="Record details"><header><h2>Record details</h2><button onClick={()=>setSelected(null)}>Close details</button></header><dl className="moduleDetail">{Object.entries(selected).map(([k,v])=><div key={k}><dt>{k.replaceAll('_',' ')}</dt><dd>{text(v)}</dd></div>)}</dl><div className="refActions">{resource==='alerts'&&!selected.acknowledged_at&&<button disabled={busy} onClick={()=>acknowledge(selected)}>Acknowledge alert</button>}{resource==='threats'&&selected.status!=='RESOLVED'&&<button disabled={busy} onClick={()=>resolve(selected)}>Mark resolved</button>}{resource==='support'&&selected.status!=='RESOLVED'&&<button disabled={busy} onClick={async()=>{if(connected){if(!await write({id:selected.id,status:'RESOLVED'},'PATCH'))return}else setRows(r=>r.map(x=>x.id===selected.id?{...x,status:'RESOLVED'}:x));setSelected(null);setNotice('Ticket resolved.')}}>Resolve ticket</button>}<button onClick={()=>exportCsv([selected],'webshield-record')}>Export record</button></div></section>}
 </div>;
}

function CommandBars(){return <span className="refBars">{[12,20,15,28,18,34,24,42].map((v,i)=><i key={i} style={{height:v}}/>)}</span>}

function CommandRing({value}:{value:number}){return <div className="refRing" style={{background:`conic-gradient(#00edb1 ${value*3.6}deg,#0b2736 0)`}}><div><strong>{value}</strong><span>/ 100</span></div></div>}

export function ConnectedCommandCenter({base='/app'}:{base?:string}){
 const [data,setData]=useState<Dashboard|null>(null),[error,setError]=useState(''),[paused,setPaused]=useState(false),[range,setRange]=useState('Last 24 hours'),[refresh,setRefresh]=useState(0);
 useEffect(()=>{if(paused)return;const controller=new AbortController();let active=true;async function load(){try{const r=await fetch(apiPath('/api/dashboard'),{cache:'no-store',signal:controller.signal});const b=await r.json();if(!r.ok||!b.ok)throw Error(b.error?.message||'Telemetry unavailable');if(active){setData(b.data);setError('')}}catch(e){if(active&&!controller.signal.aborted)setError(e instanceof Error?e.message:'Telemetry unavailable')}}load();const timer=setInterval(load,15000);return()=>{active=false;controller.abort();clearInterval(timer)}},[paused,refresh]);
 const days=range.includes('7')?7:1;
 const series:TrafficPoint[]=useMemo(()=>bucketSessions(data?.sessionsData||[],Date.now(),days),[data,days]);
 if(error)return <section className="refPanel moduleError" role="alert"><h2>Unable to load connected telemetry</h2><p>{error}</p><button onClick={()=>setRefresh(r=>r+1)}>Retry</button></section>;
 if(!data)return <section className="refPanel"><p role="status">Loading connected Supabase workspace…</p></section>;

 const metrics=data.metrics||{};
 const websites=Number(metrics.websites||0);
 const threats=Number(metrics.threats||0);
 const alerts=Number(metrics.openAlerts||0);
 const blocked=Number(metrics.blockedRequests||0);
 const activeVisitors=Number(metrics.activeVisitors||0);
 const score=websites>0?Math.max(0,100-Math.min(100,threats*12+alerts*6+blocked*2)):0;
 const severity=(data.threats||[]).reduce((acc:Record<string,number>,row)=>{const key=String(row.severity||'LOW').toUpperCase();acc[key]=(acc[key]||0)+1;return acc},{});
 const riskLabel=websites===0?'Not Assessed':score>=85?'Low Risk':score>=65?'Medium Risk':'High Risk';
 const visitors=data.visitorsData||[];
 const countryCounts=new Map<string,number>();
 visitors.forEach(v=>countryCounts.set(v.country||'Unknown',(countryCounts.get(v.country||'Unknown')||0)+1));
 const topCountry=[...countryCounts.entries()].sort((a,b)=>b[1]-a[1])[0]?.[0]||'—';

 return <div className="connectedOverview">
   <div className="refActions">
     <Link className="refPrimary" href={base+'/websites'}><Icon name="plus"/> Add Website</Link>
     <Link href={base+'/websites'}>▶　Run Scan</Link>
     <Link href={base+'/database-security'}>▤　Connect Database</Link>
   </div>

   <div className="refMetrics">
     <Link href={base+'/websites'} className="refMetric tone0">
       <div className="refMetricIcon"><Icon name="shield" size={29}/></div>
       <div><span>Security Score</span><strong>{score}<small> / 100</small></strong><p>{websites? 'Derived from current recorded events':'Add a website to calculate posture'}</p></div><CommandBars/>
     </Link>
     <Link href={base+'/websites'} className="refMetric tone1">
       <div className="refMetricIcon"><Icon name="globe" size={29}/></div>
       <div><span>Websites</span><strong>{websites}</strong><p>Connected websites</p></div><CommandBars/>
     </Link>
     <Link href={base+'/threat-center'} className="refMetric tone2">
       <div className="refMetricIcon"><Icon name="threat" size={29}/></div>
       <div><span>Threats</span><strong>{threats}</strong><p>Recorded security threats</p></div><CommandBars/>
     </Link>
     <Link href={base+'/alerts'} className="refMetric tone3">
       <div className="refMetricIcon"><Icon name="bell" size={29}/></div>
       <div><span>Alerts</span><strong>{alerts}</strong><p>Needs your attention</p></div><CommandBars/>
     </Link>
   </div>

   <div className="refColumns">
     <section className="refPanel">
       <header><Icon name="chart" size={25}/><div><h2>Security Activity</h2><p>Website traffic, threats and security events from your connected workspace.</p></div><select aria-label="Chart range" value={range} onChange={e=>setRange(e.target.value)}><option>Last 24 hours</option><option>Last 7 days</option></select></header>
       <ActivityGraph data={series} paused={paused} range={range}/>
     </section>
     <section className="refPanel">
       <header><Icon name="shield" size={25}/><div><h2>Risk Summary</h2><p>Current risk from recorded WebShield events.</p></div></header>
       <div className="refRisk"><CommandRing value={score}/><div><span className="refBadge low">{riskLabel}</span><p>{websites? 'Based on current recorded threats, alerts and blocks.':'Connect and scan a website to assess posture.'}</p>{['Critical Issues','High Risk','Medium Risk','Low Risk'].map((s,i)=><p key={s}><span className={'refDot dot'+i}/>{s}<b>{[severity.CRITICAL||0,severity.HIGH||0,severity.MEDIUM||0,severity.LOW||0][i]}</b></p>)}</div></div>
     </section>
   </div>

   <div className="refBottom">
     <section className="refPanel">
       <header><Icon name="globe" size={25}/><div><h2>Website Security</h2><p>Your connected websites and current integration status.</p></div><Link href={base+'/websites'}>Add Website</Link></header>
       {data.websitesData?.length?data.websitesData.slice(0,5).map(site=><Link className="connectedListItem" href={base+'/websites'} key={text(site.id)}><span>{text(site.domain)}</span><b>{text(site.integration_status)}</b></Link>):<p>No websites added yet.</p>}
     </section>
     <section className="refPanel">
       <header><Icon name="threat" size={25}/><div><h2>Recent Threats</h2><p>Latest recorded security events.</p></div></header>
       {data.threats?.length?data.threats.slice(0,4).map(t=><Link className="refThreat" href={base+'/threat-center'} key={text(t.id)}><Icon name="threat"/><div>{text(t.type)}<small>{text(t.target_url)}</small></div><span className={'refBadge '+String(t.severity||'LOW').toLowerCase()}>{text(t.severity)}</span></Link>):<p>No threat events recorded.</p>}
     </section>
     <div className="refStack">
       <section className="refPanel"><header><Icon name="chart" size={25}/><div><h2>Live Traffic</h2></div><Link href={base+'/live-traffic'}>View →</Link></header><div className="refMiniStats"><div>Live Visitors<strong>{activeVisitors}</strong></div><div>Top Country<strong>{topCountry}</strong></div><div>Blocked<strong>{blocked}</strong></div></div></section>
       <section className="refPanel"><h2>Protection Readiness</h2><p className="refCheck">{websites?'✓':'○'}　Website Added</p><p className="refCheck">{data.websitesData?.some(s=>Boolean(s.verified_at))?'✓':'○'}　Ownership Verified</p><p className="refCheck">{data.websitesData?.some(s=>String(s.integration_status).includes('CONNECTED'))?'✓':'○'}　Collector Connected</p><Link href={base+'/websites'}>Manage protection →</Link></section>
     </div>
   </div>

   <div className="moduleToolbar"><select aria-label="Telemetry time range" value={range} onChange={e=>setRange(e.target.value)}><option>Last 24 hours</option><option>Last 7 days</option></select><button onClick={()=>setPaused(!paused)}>{paused?'Resume updates':'Pause updates'}</button><button onClick={()=>setRefresh(r=>r+1)}>Refresh now</button><button onClick={()=>exportCsv(visitors.map(v=>({...v})),'webshield-visitors')}>Export visitors</button></div>
 </div>;
}

type Session={occurred_at:string;visitor_id?:string;status?:string;requested_url?:string};
type Visitor={id:string;country?:string;city?:string;ip_address?:string;device?:string;browser?:string;last_seen_at?:string};
type Dashboard={metrics?:Record<string,number>;websitesData?:Row[];visitorsData?:Visitor[];sessionsData?:Session[];threats?:Row[];alerts?:Row[]};
export function ConnectedOverview({page,base='/app'}:{page:string;base?:string}){
 const [siteId,setSiteId]=useState('ALL');
 const [data,setData]=useState<Dashboard|null>(null),[error,setError]=useState(''),[paused,setPaused]=useState(false),[range,setRange]=useState('Last 24 hours'),[country,setCountry]=useState(''),[selected,setSelected]=useState<Visitor|null>(null),[refresh,setRefresh]=useState(0);
 useEffect(()=>{if(paused)return;const controller=new AbortController();let active=true;async function load(){try{const r=await fetch(apiPath('/api/dashboard'),{cache:'no-store',signal:controller.signal});const b=await r.json();if(!r.ok||!b.ok)throw Error(b.error?.message||'Telemetry unavailable');if(active){setData(b.data);setError('')}}catch(e){if(active&&!controller.signal.aborted)setError(e instanceof Error?e.message:'Telemetry unavailable')}}load();const timer=setInterval(load,15000);return()=>{active=false;controller.abort();clearInterval(timer)}},[paused,refresh]);
 const days=range.includes('7')?7:1;const cutoff=Date.now()-days*86400000;const visitors=(data?.visitorsData||[]).filter(v=>(siteId==='ALL'||v.website_id===siteId)&&v.last_seen_at&&new Date(v.last_seen_at).getTime()>=cutoff);const sessions=(data?.sessionsData||[]).filter(s=>(siteId==='ALL'||s.website_id===siteId)&&new Date(s.occurred_at).getTime()>=cutoff);
 const series:TrafficPoint[]=useMemo(()=>bucketSessions(sessions,Date.now(),days),[data,days,siteId]);
 const countries=useMemo(()=>{const counts=new Map<string,number>();visitors.forEach(v=>counts.set(v.country||'Unknown',(counts.get(v.country||'Unknown')||0)+1));return [...counts.entries()].sort((a,b)=>b[1]-a[1])},[data,range]);
 const locations=countries.flatMap(([name,count])=>{const match=sampleLocations.find(p=>p.name.toLowerCase()===name.toLowerCase()||p.code.toLowerCase()===name.toLowerCase());return match?[{...match,name,count,risk:false}]:[]});
 if(error)return <section className="refPanel moduleError" role="alert"><h2>Unable to load connected telemetry</h2><p>{error}</p><button onClick={()=>setRefresh(r=>r+1)}>Retry</button></section>;
 if(!data)return <section className="refPanel"><p role="status">Loading connected Supabase workspace…</p></section>;
 const traffic=page==='live-traffic'||page==='live-visitors';
 return <div className="connectedOverview"><div className="moduleToolbar"><select aria-label="Website filter" value={siteId} onChange={e=>{setSiteId(e.target.value);setCountry('');setSelected(null)}}><option value="ALL">All connected websites</option>{(data.websitesData||[]).map(w=><option key={w.id} value={w.id}>{w.domain}</option>)}</select><select aria-label="Telemetry time range" value={range} onChange={e=>setRange(e.target.value)}><option>Last 24 hours</option><option>Last 7 days</option></select><button onClick={()=>setPaused(!paused)}>{paused?'Resume updates':'Pause updates'}</button><button onClick={()=>setRefresh(r=>r+1)}>Refresh now</button><button onClick={()=>exportCsv(visitors.map(v=>({...v})),'webshield-visitors')}>Export visitors</button></div><div className="refMetrics">{[['Websites',siteId==='ALL'?(data.websitesData||[]).length:1,base+'/websites'],['Visitors',visitors.length,base+'/live-traffic'],['Sessions',sessions.length,base+'/live-traffic'],['Blocked Requests',sessions.filter(s=>s.status==='BLOCKED').length,base+'/threat-center']].map(([label,value,href])=><Link className="refMetric moduleMetric" href={String(href)} key={label}><span>{label}</span><strong>{value}</strong><small>View {String(label).toLowerCase()} →</small></Link>)}</div>{traffic&&<div className="refColumns"><section className="refPanel"><header><div><h2>Live Visitor Map</h2><p>Country-centre locations from recorded website events. Locations are approximate.</p></div></header><VisitorMap locations={locations} paused={paused} onSelect={p=>setCountry(p.name)}/></section><section className="refPanel"><h2>Top Countries</h2>{countries.length?countries.map(([name,count])=><button className="refCountry" key={name} onClick={()=>setCountry(name)}><span>{name}</span><b>{count}</b><i><em style={{width:`${count/Math.max(1,visitors.length)*100}%`}}/></i></button>):<p>No geographic data received yet.</p>}</section></div>}<section className="refPanel"><header><div><h2>{traffic?'Traffic Activity':'Security Activity'}</h2><p>{range} · {sessions.length} recent collected sessions in current window · Limited to latest 5,000 sessions and 1,000 visitor records · refreshes every 15 seconds</p></div></header><ActivityGraph data={series} paused={paused} range={range}/></section>{!traffic&&<div className="refEqual"><section className="refPanel"><h2>Connected websites</h2>{data.websitesData?.length?data.websitesData.map(s=><Link className="connectedListItem" href={base+'/websites'} key={text(s.id)}><span>{text(s.domain)}</span><b>{text(s.integration_status)}</b></Link>):<p>No websites yet.</p>}<Link className="refPrimary" href={base+'/websites'}>Add or connect website</Link></section><section className="refPanel"><h2>Recent security events</h2>{data.threats?.length?data.threats.map(t=><Link className="connectedListItem" href={base+'/threat-center'} key={text(t.id)}>{text(t.type)}<b>{text(t.severity)}</b></Link>):<p>No threat events recorded.</p>}<Link href={base+'/database-security'} className="refPrimary">Open Database Security</Link></section></div>}<section className="refPanel"><header><div><h2>Connected website status</h2><p>Telemetry status is based on received collector events—not a guarantee of full HTTP request coverage.</p></div></header>{(data.websitesData||[]).length?<div className="refTable"><table><thead><tr><th>Website</th><th>Integration</th><th>Last event</th><th>Visitors (selected period)</th><th>Sessions (selected period)</th></tr></thead><tbody>{(data.websitesData||[]).filter(w=>siteId==='ALL'||w.id===siteId).map(w=><tr key={w.id}><td>{w.domain}</td><td>{w.integration_status||'NOT CONNECTED'}</td><td>{w.last_event_at?new Date(w.last_event_at).toLocaleString():'No events yet'}</td><td>{visitors.filter(v=>v.website_id===w.id).length}</td><td>{sessions.filter(s=>s.website_id===w.id).length}</td></tr>)}</tbody></table></div>:<p>No websites added. <Link href={base+'/websites'}>Connect a website →</Link></p>}</section><section className="refPanel"><header><div><h2>Visitor Stream {country&&`· ${country}`}</h2><p>Collected records, with no simulated traffic.</p></div>{country&&<button onClick={()=>setCountry('')}>Clear country filter</button>}</header>{visitors.length?<div className="refTable"><table><thead><tr>{['Country','City','IP address','Device','Browser','Last seen','Action'].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{visitors.filter(v=>!country||v.country===country).map(v=><tr key={v.id}><td>{v.country||'Unknown'}</td><td>{v.city||'Unknown'}</td><td>{v.ip_address||'Not captured'}</td><td>{v.device||'Unknown'}</td><td>{v.browser||'Unknown'}</td><td>{v.last_seen_at?new Date(v.last_seen_at).toLocaleString():'Unknown'}</td><td><button onClick={()=>setSelected(v)}>View session</button></td></tr>)}</tbody></table></div>:<p>No visitors collected during this period. <Link href={base+'/websites'}>Install the website collector to start monitoring →</Link></p>}</section>{selected&&<section className="refPanel moduleSelected"><header><h2>Visitor details</h2><button onClick={()=>setSelected(null)}>Close details</button></header><dl className="moduleDetail">{Object.entries(selected).map(([k,v])=><div key={k}><dt>{k}</dt><dd>{text(v)}</dd></div>)}</dl><h3>Recent pages</h3>{sessions.filter(s=>s.visitor_id===selected.id).map((s,i)=><p key={i}>{s.requested_url} · {s.status} · {new Date(s.occurred_at).toLocaleString()}</p>)}</section>}</div>;
}
