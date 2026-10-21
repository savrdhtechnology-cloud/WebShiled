import {PGlite} from '@electric-sql/pglite';
import {pgcrypto} from '@electric-sql/pglite/contrib/pgcrypto';
import {readFileSync,readdirSync} from 'node:fs';
const dir=new URL('../supabase/migrations',import.meta.url).pathname;
const db=new PGlite({extensions:{pgcrypto}});
await db.exec(`
create role anon; create role authenticated; create role service_role;
create schema auth;
create table auth.users(id uuid primary key default gen_random_uuid(), email text, raw_user_meta_data jsonb default '{}');
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true),'')::uuid $$;
create function public.rls_auto_enable() returns void language sql as $$ select $$;
`);
const files=readdirSync(dir).filter(f=>f.endsWith('.sql')).sort();
for(const f of files){
  try{await db.exec(readFileSync(dir+'/'+f,'utf8'));void f}catch(e){console.error('Migration failed',f,e.message);process.exit(1)}
}
// idempotency of 0006
await db.exec(readFileSync(dir+'/'+files.at(-1),'utf8'));
await db.exec(`insert into auth.users(email) values('a@b.com')`);
const rows=(await db.query(`select tm.role,(select count(*)::int from plans) plans from organizations o join team_members tm on tm.organization_id=o.id`)).rows;
if(rows.length!==1||rows[0].role!=='OWNER'||rows[0].plans!==4)throw new Error('Signup provisioning failed: '+JSON.stringify(rows));
console.log('Migrations 0001-'+files.at(-1).slice(0,4)+' apply cleanly and 0006 is re-runnable.');
