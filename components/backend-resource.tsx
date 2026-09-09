"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type Props={resource:string;title:string;description:string;allowFirewallCreate?:boolean};

function pretty(value:any){
  if(value===null||value===undefined)return "—";
  if(typeof value==="boolean")return value?"YES":"NO";
  if(typeof value==="object")return JSON.stringify(value);
  return String(value);
}

export function BackendResource({resource,title,description,allowFirewallCreate=false}:Props){
  const [data,setData]=useState<any>(null);
  const [error,setError]=useState("");
  const [loading,setLoading]=useState(true);
  const [ruleName,setRuleName]=useState("");
  const [action,setAction]=useState("BLOCK");

  async function load(){
    setLoading(true);setError("");
    try{
      const r=await fetch(`/api/${resource}`,{cache:"no-store"});
      const b=await r.json();
      if(!r.ok||!b.ok)throw new Error(b?.error?.message||"Backend data unavailable.");
      setData(b.data);
    }catch(e){setError(e instanceof Error?e.message:"Backend data unavailable.");}
    finally{setLoading(false);}
  }
  useEffect(()=>{load();},[resource]);

  async function addRule(e:FormEvent){
    e.preventDefault(); setError("");
    try{
      const r=await fetch("/api/firewall",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:ruleName,action,conditions:[]})});
      const b=await r.json();
      if(!r.ok||!b.ok)throw new Error(b?.error?.message||"Could not save firewall rule.");
      setRuleName(""); await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not save firewall rule.");}
  }

  const rows=useMemo(()=>Array.isArray(data)?data:Array.isArray(data?.rules)?data.rules:[],[data]);
  const columns=useMemo(()=>rows.length?Object.keys(rows[0]).filter(k=>!['metadata','conditions'].includes(k)).slice(0,8):[],[rows]);
  const scalars=useMemo(()=>data&& !Array.isArray(data)?Object.entries(data).filter(([,v])=>['string','number','boolean'].includes(typeof v)):[],[data]);

  return <div className="pageWrap">
    <div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> {title}</div><h1>{title}</h1><p>{description}</p></div><span className="statusTag safe">SUPABASE BACKEND</span></div>

    {allowFirewallCreate&&<article className="panel" style={{marginBottom:16}}><div className="panelHead"><div><h3>Create Firewall Rule</h3><p>The rule is stored in the backend. Automatic enforcement starts only after a real provider_rule_id is connected.</p></div></div><form onSubmit={addRule} style={{display:"grid",gridTemplateColumns:"1fr 180px auto",gap:10,marginTop:14}}><input value={ruleName} onChange={e=>setRuleName(e.target.value)} placeholder="Rule name" required style={{height:44,borderRadius:10,border:"1px solid rgba(120,190,225,.15)",background:"#091522",color:"#edf8ff",padding:"0 13px"}}/><select value={action} onChange={e=>setAction(e.target.value)} style={{height:44,borderRadius:10,border:"1px solid rgba(120,190,225,.15)",background:"#091522",color:"#edf8ff",padding:"0 13px"}}><option>BLOCK</option><option>ALLOW</option><option>CHALLENGE</option><option>RATE_LIMIT</option></select><button className="btn" type="submit">Save Rule</button></form></article>}

    {loading&&<article className="panel"><p>Loading backend data…</p></article>}
    {error&&<article className="panel"><div className="formNotice error">{error}</div><p>Demo sessions do not receive fake telemetry. Use a real registered WebShield account for database-backed modules.</p></article>}

    {!loading&&!error&&data&&<>
      {scalars.length>0&&<div className="metricGrid compact">{scalars.slice(0,6).map(([k,v])=><article className="metricCard" key={k}><span>{k.replaceAll('_',' ')}</span><strong>{pretty(v)}</strong><small>Backend value</small></article>)}</div>}
      <article className="panel tablePanel" style={{marginTop:16}}><div className="panelHead"><div><h3>{title} Records</h3><p>Loaded directly from WebShield backend tables.</p></div></div>{rows.length?<div className="tableScroll"><table><thead><tr>{columns.map(c=><th key={c}>{c.replaceAll('_',' ')}</th>)}</tr></thead><tbody>{rows.map((row:any,i:number)=><tr key={row.id||i}>{columns.map(c=><td key={c}>{pretty(row[c])}</td>)}</tr>)}</tbody></table></div>:<p>No records yet.</p>}</article>
    </>}
  </div>;
}
