import 'server-only';
import type {SupabaseClient} from '@supabase/supabase-js';
import {runPassiveScan} from './passive-scanner';
export async function scanMonitoredWebsite(client:SupabaseClient,site:Record<string,any>){
 const now=new Date();const next=new Date(now.getTime()+Math.max(15,site.monitoring_interval_minutes||1440)*60000).toISOString();
 let claim=client.from('websites').update({next_scan_at:new Date(now.getTime()+5*60000).toISOString()}).eq('id',site.id).eq('organization_id',site.organization_id);
 claim=site.next_scan_at?claim.eq('next_scan_at',site.next_scan_at):claim.is('next_scan_at',null);
 const claimed=await claim.select('id').maybeSingle();if(claimed.error)throw claimed.error;if(!claimed.data)return {id:site.id,skipped:true};
 try{
  let scan;try{scan=await runPassiveScan(site.last_scan?.finalUrl||'https://'+site.domain)}catch(error){if(String(site.domain).startsWith('www.'))throw error;scan=await runPassiveScan('https://www.'+site.domain)}
  const previous=new Set((site.last_scan?.findings||[]).map((f:{title:string;severity:string})=>f.title+':'+f.severity));
  const fresh=scan.findings.filter(f=>f.severity!=='INFO'&&!previous.has(f.title+':'+f.severity));
  const storedScan={...scan,monitorAcknowledgedAt:fresh.length?null:site.last_scan?.monitorAcknowledgedAt||null};
  const history=await client.from('security_scan_runs').insert({organization_id:site.organization_id,website_id:site.id,status:'COMPLETED',security_score:scan.securityScore,security_grade:scan.grade,overall_risk:scan.overallRisk,finding_counts:scan.findingCounts,findings:scan.findings,scan_payload:storedScan,started_at:now.toISOString(),completed_at:new Date().toISOString()});if(history.error)throw history.error;
  const saved=await client.from('websites').update({next_scan_at:next,last_scan:storedScan,last_scan_at:scan.scannedAt,security_score:scan.securityScore,security_grade:scan.grade,overall_risk:scan.overallRisk}).eq('id',site.id).eq('organization_id',site.organization_id);if(saved.error)throw saved.error;
  return {id:site.id,domain:site.domain,findings:scan.findings.length,completed:true};
 }catch(error){const message=error instanceof Error?error.message:'Scan failed';await client.from('websites').update({next_scan_at:new Date(Date.now()+15*60000).toISOString()}).eq('id',site.id).eq('organization_id',site.organization_id);await client.from('security_scan_runs').insert({organization_id:site.organization_id,website_id:site.id,status:'FAILED',started_at:now.toISOString(),completed_at:new Date().toISOString(),error_message:message});return {id:site.id,domain:site.domain,error:message};}
}
