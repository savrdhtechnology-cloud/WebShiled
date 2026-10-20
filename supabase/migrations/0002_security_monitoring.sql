-- WebShield security monitoring extension
-- Additive only: preserves existing website/collector/telemetry data.

alter table public.websites
  add column if not exists monitoring_enabled boolean not null default false,
  add column if not exists monitoring_interval_minutes integer not null default 1440,
  add column if not exists security_score integer,
  add column if not exists security_grade text,
  add column if not exists overall_risk text,
  add column if not exists last_scan_at timestamptz,
  add column if not exists next_scan_at timestamptz,
  add column if not exists last_scan jsonb not null default '{}'::jsonb;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'websites_monitoring_interval_check'
      and conrelid = 'public.websites'::regclass
  ) then
    alter table public.websites
      add constraint websites_monitoring_interval_check
      check (monitoring_interval_minutes between 15 and 10080);
  end if;
end $$;

create table if not exists public.security_scan_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid not null references public.websites(id) on delete cascade,
  status text not null default 'COMPLETED'
    check (status in ('RUNNING','COMPLETED','FAILED')),
  security_score integer check (security_score between 0 and 100),
  security_grade text,
  overall_risk text,
  finding_counts jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  scan_payload jsonb not null default '{}'::jsonb,
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  error_message text,
  created_at timestamptz not null default now()
);

create index if not exists idx_security_scan_runs_site_time
  on public.security_scan_runs(website_id, created_at desc);

create index if not exists idx_security_scan_runs_org_time
  on public.security_scan_runs(organization_id, created_at desc);

alter table public.security_scan_runs enable row level security;

drop policy if exists "security_scan_runs_member_read" on public.security_scan_runs;
create policy "security_scan_runs_member_read"
on public.security_scan_runs for select to authenticated
using (
  exists (
    select 1 from public.team_members tm
    where tm.organization_id = security_scan_runs.organization_id
      and tm.user_id = (select auth.uid())
  )
);

drop policy if exists "security_scan_runs_manager_write" on public.security_scan_runs;
create policy "security_scan_runs_manager_write"
on public.security_scan_runs for all to authenticated
using (
  exists (
    select 1 from public.team_members tm
    where tm.organization_id = security_scan_runs.organization_id
      and tm.user_id = (select auth.uid())
      and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')
  )
)
with check (
  exists (
    select 1 from public.team_members tm
    where tm.organization_id = security_scan_runs.organization_id
      and tm.user_id = (select auth.uid())
      and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')
  )
);
