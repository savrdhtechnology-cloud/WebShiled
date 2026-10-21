-- WebShield 0006: live monitoring, Data Guard, alert delivery and missing write policies.
--
-- Safe to run more than once. Additive only: no existing data is removed.
-- Requires migrations 0001-0004 (and 0003 for Database Security) to be applied first.

do $$
begin
  if to_regclass('public.websites') is null then
    raise exception 'WebShield base schema missing: apply 0001_webshield_v1.sql first.';
  end if;
  if to_regclass('public.database_connections') is null then
    raise exception 'Database Security schema missing: apply 0003_database_security.sql first.';
  end if;
  if to_regclass('public.security_scan_runs') is null then
    raise exception 'Monitoring schema missing: apply 0002_security_monitoring.sql first.';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Websites: uptime, TLS certificate and server-ingest credentials
-- ---------------------------------------------------------------------------
alter table public.websites
  add column if not exists uptime_status text not null default 'UNKNOWN',
  add column if not exists last_uptime_check_at timestamptz,
  add column if not exists last_response_ms integer,
  add column if not exists last_status_code integer,
  add column if not exists consecutive_failures integer not null default 0,
  add column if not exists ssl_expires_at timestamptz,
  add column if not exists ssl_issuer text,
  add column if not exists ingest_secret_hash text,
  add column if not exists ingest_secret_hint text,
  add column if not exists last_ingest_at timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'websites_uptime_status_check' and conrelid = 'public.websites'::regclass) then
    alter table public.websites add constraint websites_uptime_status_check
      check (uptime_status in ('UNKNOWN','UP','DEGRADED','DOWN'));
  end if;
end $$;

-- Passive monitoring is safe for every registered website; turn it on by default.
alter table public.websites alter column monitoring_enabled set default true;
update public.websites set monitoring_enabled = true where monitoring_enabled = false and last_scan_at is null;

create table if not exists public.uptime_checks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid not null references public.websites(id) on delete cascade,
  ok boolean not null,
  status_code integer,
  response_ms integer,
  ssl_days_left integer,
  error text,
  checked_at timestamptz not null default now()
);
create index if not exists idx_uptime_checks_site_time on public.uptime_checks(website_id, checked_at desc);
create index if not exists idx_uptime_checks_org_time on public.uptime_checks(organization_id, checked_at desc);
alter table public.uptime_checks enable row level security;
drop policy if exists "uptime_checks_member_read" on public.uptime_checks;
create policy "uptime_checks_member_read" on public.uptime_checks for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = uptime_checks.organization_id and tm.user_id = (select auth.uid())));

drop policy if exists "uptime_checks_security_insert" on public.uptime_checks;
create policy "uptime_checks_security_insert" on public.uptime_checks for insert to authenticated
with check (exists(select 1 from public.team_members tm where tm.organization_id = uptime_checks.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

-- Request-level telemetry from the server ingest integration.
alter table public.visitor_sessions
  add column if not exists client_ip inet,
  add column if not exists user_agent text,
  add column if not exists source text not null default 'browser';
create index if not exists idx_sessions_site_ip_time on public.visitor_sessions(website_id, client_ip, occurred_at desc);
create index if not exists idx_threats_org_ip_time on public.threat_events(organization_id, source_ip, occurred_at desc);

-- ---------------------------------------------------------------------------
-- Database Security: Data Guard (change capture inside the monitored database)
-- ---------------------------------------------------------------------------
alter table public.database_connections
  add column if not exists guard_enabled boolean not null default false,
  add column if not exists guard_installed_at timestamptz,
  add column if not exists guard_tables text[] not null default '{}',
  add column if not exists guard_anon_insert_tables text[] not null default '{}',
  add column if not exists guard_trusted_db_users text[] not null default '{}',
  add column if not exists guard_cursor bigint not null default 0,
  add column if not exists guard_last_poll_at timestamptz,
  add column if not exists guard_last_error text,
  add column if not exists audit_interval_minutes integer not null default 1440,
  add column if not exists next_audit_at timestamptz;

create table if not exists public.database_activity_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  connection_id uuid not null references public.database_connections(id) on delete cascade,
  source_id bigint not null,
  occurred_at timestamptz not null,
  table_schema text not null,
  table_name text not null,
  operation text not null,
  db_user text,
  jwt_role text,
  user_id text,
  client_ip text,
  row_pk text,
  changed_columns text[] not null default '{}',
  suspicious boolean not null default false,
  severity text not null default 'INFO' check (severity in ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  reasons text[] not null default '{}',
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  unique (connection_id, source_id)
);
create index if not exists idx_db_activity_org_time on public.database_activity_events(organization_id, occurred_at desc);
create index if not exists idx_db_activity_suspicious on public.database_activity_events(organization_id, occurred_at desc) where suspicious;
alter table public.database_activity_events enable row level security;
drop policy if exists "db_activity_member_read" on public.database_activity_events;
create policy "db_activity_member_read" on public.database_activity_events for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = database_activity_events.organization_id and tm.user_id = (select auth.uid())));
drop policy if exists "db_activity_security_insert" on public.database_activity_events;
create policy "db_activity_security_insert" on public.database_activity_events for insert to authenticated
with check (exists(select 1 from public.team_members tm where tm.organization_id = database_activity_events.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));
drop policy if exists "db_activity_security_update" on public.database_activity_events;
create policy "db_activity_security_update" on public.database_activity_events for update to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = database_activity_events.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = database_activity_events.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

-- ---------------------------------------------------------------------------
-- Alerts: deduplication, source context and delivery channels
-- ---------------------------------------------------------------------------
alter table public.alerts
  add column if not exists source text not null default 'system',
  add column if not exists connection_id uuid references public.database_connections(id) on delete set null,
  add column if not exists dedupe_key text,
  add column if not exists metadata jsonb not null default '{}'::jsonb,
  add column if not exists occurrences integer not null default 1,
  add column if not exists last_seen_at timestamptz not null default now(),
  add column if not exists acknowledged_by uuid references auth.users(id) on delete set null;
create unique index if not exists idx_alerts_open_dedupe
  on public.alerts(organization_id, dedupe_key)
  where acknowledged_at is null and dedupe_key is not null;
create index if not exists idx_alerts_org_time on public.alerts(organization_id, created_at desc);

alter table public.notifications
  add column if not exists recipient text,
  add column if not exists error text;

create table if not exists public.alert_channels (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  enabled boolean not null default true,
  email_recipients text[] not null default '{}',
  webhook_url text,
  min_severity text not null default 'HIGH' check (min_severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  updated_at timestamptz not null default now()
);
alter table public.alert_channels enable row level security;
drop policy if exists "alert_channels_member_read" on public.alert_channels;
create policy "alert_channels_member_read" on public.alert_channels for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = alert_channels.organization_id and tm.user_id = (select auth.uid())));
drop policy if exists "alert_channels_manager_write" on public.alert_channels;
create policy "alert_channels_manager_write" on public.alert_channels for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = alert_channels.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = alert_channels.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN')));

-- ---------------------------------------------------------------------------
-- Missing write policies. Without these, "Acknowledge alert", "Mark resolved",
-- "Resolve ticket" and IP/country rules silently failed under RLS.
-- ---------------------------------------------------------------------------
drop policy if exists "alerts_security_update" on public.alerts;
create policy "alerts_security_update" on public.alerts for update to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = alerts.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = alerts.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "alerts_security_insert" on public.alerts;
create policy "alerts_security_insert" on public.alerts for insert to authenticated
with check (exists(select 1 from public.team_members tm where tm.organization_id = alerts.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "threats_security_update" on public.threat_events;
create policy "threats_security_update" on public.threat_events for update to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = threat_events.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = threat_events.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "tickets_security_update" on public.support_tickets;
create policy "tickets_security_update" on public.support_tickets for update to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = support_tickets.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = support_tickets.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "ip_rules_manager_write" on public.ip_rules;
create policy "ip_rules_manager_write" on public.ip_rules for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = ip_rules.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = ip_rules.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "country_rules_manager_write" on public.country_rules;
create policy "country_rules_manager_write" on public.country_rules for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id = country_rules.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id = country_rules.organization_id and tm.user_id = (select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

alter table public.ip_rules
  add column if not exists expires_at timestamptz,
  add column if not exists created_by uuid references auth.users(id) on delete set null,
  add column if not exists hits bigint not null default 0;
create index if not exists idx_ip_rules_org on public.ip_rules(organization_id);

-- Plans seed: some deployments ran 0001 without the seed. Insert idempotently.
insert into public.plans(code,name,website_limit,monthly_visitor_limit,security_event_limit,retention_days,reports_access,api_access,team_member_limit)
values
('FREE','Free',1,10000,10000,7,true,false,1),
('STARTER','Starter',3,100000,100000,30,true,false,3),
('BUSINESS','Business',10,1000000,1000000,90,true,true,10),
('ENTERPRISE','Enterprise',null,null,null,null,true,true,null)
on conflict (code) do nothing;
