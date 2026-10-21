import {PGlite} from '@electric-sql/pglite';
import assert from 'node:assert/strict';
import * as g from '../lib/database-security/guard.ts';
const db=new PGlite();
await db.exec(`create role anon; create role authenticated; create role service_role;
create table public.users(id serial primary key, email text, role text default 'user');
create table public.leads(id serial primary key, name text);
grant all on public.users, public.leads to anon, authenticated, service_role;
grant usage, select on all sequences in schema public to anon, authenticated, service_role;`);
await db.exec(g.guardInstallSql(['users','public.leads']));
await db.exec(g.guardInstallSql(['users','public.leads'])); // re-sync idempotent
assert.deepEqual((await db.query(g.guardStatusSql())).rows[0].watched_tables,['public.leads','public.users']);
// direct (postgres)
await db.exec(`insert into users(email) values ('a@x.com'),('b@x.com')`);
// anon via API
await db.exec(`begin; set local role anon; select set_config('request.jwt.claims','{"role":"anon"}',true); select set_config('request.headers','{"x-forwarded-for":"1.2.3.4, 10.0.0.1"}',true);
insert into leads(name) values('lead'); update users set email='hack' where id=1; commit;`);
// authenticated user escalating role
await db.exec(`begin; set local role authenticated; select set_config('request.jwt.claims','{"role":"authenticated","sub":"u-1"}',true);
update users set role='admin' where id=2; update users set role='admin' where id=2; commit;`);
// backend
await db.exec(`begin; set local role service_role; select set_config('request.jwt.claims','{"role":"service_role"}',true); update users set role='x' where id=2; delete from leads; commit;`);
// anon must not read the log
let denied=false; try{await db.exec(`begin; set local role anon; select * from webshield_guard.change_log; commit;`)}catch{denied=true;await db.exec('rollback')}
assert.ok(denied,'anon cannot read change log');
const rows=(await db.query(g.guardPollSql(0))).rows;

const c=g.classifyChanges(rows,{anonInsertTables:['leads'],trustedDbUsers:[]});

assert.equal(rows.length,7,'no-op update skipped');
assert.equal(c.find(x=>x.operation==='INSERT'&&x.table==='public.leads').suspicious,false);
assert.ok(c.find(x=>x.jwt_role==='anon'&&x.operation==='UPDATE').severity==='HIGH');
assert.ok(c.find(x=>x.jwt_sub==='u-1').reasons.some(r=>r.code==='PRIVILEGE_CHANGE'));
assert.ok(c.filter(x=>x.db_user==='postgres').every(x=>x.reasons.some(r=>r.code==='DIRECT_DB_WRITE')));
assert.ok(c.filter(x=>x.jwt_role==='service_role').every(x=>!x.suspicious));
const t=g.classifyChanges(rows,{anonInsertTables:['leads'],trustedDbUsers:['postgres']});
assert.ok(t.filter(x=>x.db_user==='postgres').every(x=>!x.suspicious),'trusted db user');
const many=Array.from({length:30},(_,i)=>({id:i+1,occurred_at:'2026-01-01',table_schema:'public',table_name:'leads',operation:'DELETE',db_user:'authenticated',jwt_role:'authenticated',jwt_sub:'u9',client_ip:null,row_pk:String(i),changed_columns:'{}'}));
const m=g.classifyChanges(many,{anonInsertTables:[],trustedDbUsers:[]});
assert.ok(m.every(x=>x.severity==='CRITICAL'));
const alerts=g.buildGuardAlerts('c1','CRM',c);assert.ok(alerts.some(a=>a.code==='ANON_WRITE'&&a.severity==='HIGH'),'anon write alert');
assert.throws(()=>g.parseTableName('users; drop table x'));
assert.throws(()=>g.parseTableName('auth.users'));
await db.exec(`truncate leads`);
assert.ok((await db.query(g.guardPollSql(7))).rows.some(r=>r.operation==='TRUNCATE'));
await db.exec(g.guardUninstallSql());
assert.equal((await db.query(g.guardStatusSql())).rows[0].installed,false);
await db.exec(`insert into users(email) values('ok')`); // app writes still work after uninstall
console.log('guard SQL tests passed');
