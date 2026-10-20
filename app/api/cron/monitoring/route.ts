import {NextRequest,NextResponse} from 'next/server';
import {createClient} from '@supabase/supabase-js';
import {SUPABASE_URL} from '@/lib/supabase/config';
import {scanMonitoredWebsite} from '@/lib/website-monitoring';
import {timingSafeEqual} from 'node:crypto';
export const maxDuration=300;
export async function GET(request:NextRequest){
 const secret=process.env.CRON_SECRET;const actual=request.headers.get('authorization')||'';const expected='Bearer '+secret;
 if(!secret||actual.length!==expected.length||!timingSafeEqual(Buffer.from(actual),Buffer.from(expected)))return NextResponse.json({error:'Unauthorized'},{status:401});
 const key=process.env.SUPABASE_SERVICE_ROLE_KEY;if(!key)return NextResponse.json({error:'Background monitoring is not configured'},{status:503});
 const client=createClient(SUPABASE_URL,key,{auth:{persistSession:false,autoRefreshToken:false}});const {data,error}=await client.from('websites').select('*').eq('monitoring_enabled',true).or('next_scan_at.is.null,next_scan_at.lte.'+new Date().toISOString()).order('next_scan_at',{ascending:true,nullsFirst:true}).limit(3);if(error)return NextResponse.json({error:'Could not load due websites'},{status:500});
 const results=[];for(const site of data||[])results.push(await scanMonitoredWebsite(client,site));return NextResponse.json({processed:results.length,failed:results.filter(r=>'error' in r).length});
}
