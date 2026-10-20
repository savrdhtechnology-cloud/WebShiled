export type CollectedSession={occurred_at:string;visitor_id?:string;status?:string};
export type Bucket={label:string;requests:number;visitors:number;blocked:number};
export function bucketSessions(sessions:CollectedSession[],now:number,days:number,count=48):Bucket[]{
 const duration=days*86400000,start=now-duration;
 const buckets=Array.from({length:count},(_,i)=>({label:new Date(start+i*duration/count).toLocaleString('en-IN',{hour:'2-digit',minute:'2-digit',...(days>1?{day:'2-digit',month:'short'}:{})}),requests:0,visitors:0,blocked:0}));
 const unique=buckets.map(()=>new Set<string>());
 for(const session of sessions){const time=new Date(session.occurred_at).getTime();if(!Number.isFinite(time)||time<start||time>now)continue;const index=Math.min(count-1,Math.floor((time-start)/duration*count));buckets[index].requests++;if(session.visitor_id)unique[index].add(session.visitor_id);if(session.status==='BLOCKED')buckets[index].blocked++}
 return buckets.map((b,i)=>({...b,visitors:unique[i].size}));
}
export function rowsToCsv(rows:Record<string,unknown>[]):string{
 const columns=[...new Set(rows.flatMap(Object.keys))];
 const quote=(v:unknown)=>{let value=v==null?'':typeof v==='object'?JSON.stringify(v):String(v);if(typeof v==='string'&&/^\s*[=+\-@]/.test(value))value="'"+value;return '"'+value.replaceAll('"','""')+'"'};
 return [columns.map(quote).join(','),...rows.map(row=>columns.map(c=>quote(row[c])).join(','))].join('\r\n');
}
