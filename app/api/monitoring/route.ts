import {NextRequest,NextResponse} from 'next/server';
import {getCurrentUser} from '@/lib/auth';
import {createClient} from '@/lib/supabase/server';
import {scanMonitoredWebsite} from '@/lib/website-monitoring';
export const maxDuration=300;
const fields='id,organization_id,domain,monitoring_enabled,monitoring_interval_minutes,last_scan_at,next_scan_at,security_score,overall_risk,last_scan';
export async function GET(){const user=await getCurrentUser();if(!user)return NextResponse.json({error:'Sign in required'},{status:401});const client=await createClient();const {data,error}=await client.from('websites').select(fields).eq('organization_id',user.organizationId).order('domain');if(error)return NextResponse.json({error:error.message},{status:500});return NextResponse.json({data,backgroundSchedulerConfigured:Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY&&process.env.CRON_SECRET)},{headers:{'Cache-Control':'no-store'}});}
export async function POST(request:NextRequest){
 const user=await getCurrentUser();if(!user)return NextResponse.json({error:'Sign in required'},{status:401});if(!['OWNER','ADMIN','SECURITY_ANALYST'].includes(user.role))return NextResponse.json({error:'Security analyst or administrator access required'},{status:403});
 const client=await createClient();const body=await request.json().catch(()=>null);if(!body)return NextResponse.json({error:'Invalid request'},{status:400});
 if(body.action==='settings'){
  if(!['OWNER','ADMIN'].includes(user.role))return NextResponse.json({error:'Administrator access required'},{status:403});
  const minutes=Number(body.interval);if(![15,60,360,1440].includes(minutes)||typeof body.enabled!=='boolean')return NextResponse.json({error:'Invalid monitoring settings'},{status:400});
  const result=await client.from('websites').update({monitoring_enabled:body.enabled,monitoring_interval_minutes:minutes,next_scan_at:body.enabled?new Date().toISOString():null}).eq('id',String(body.id)).eq('organization_id',user.organizationId).select('id').maybeSingle();if(result.error)return NextResponse.json({error:result.error.message},{status:500});if(!result.data)return NextResponse.json({error:'Website not found'},{status:404});return NextResponse.json({ok:true});
 }
 let query=client.from('websites').select(fields).eq('organization_id',user.organizationId);
 if(body.action==='scan')query=query.eq('id',String(body.id));else if(body.action==='due')query=query.eq('monitoring_enabled',true).or('next_scan_at.is.null,next_scan_at.lte.'+new Date().toISOString());else return NextResponse.json({error:'Unsupported action'},{status:400});
 const sites=await query.limit(3);if(sites.error)return NextResponse.json({error:sites.error.message},{status:500});const results=[];for(const site of sites.data||[])results.push(await scanMonitoredWebsite(client,site));return NextResponse.json({results});
}
