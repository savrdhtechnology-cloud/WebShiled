-- WebShield Database Security V2
-- Adds encrypted provider connections, scan history, findings and approved remediation jobs.

create table if not exists public.database_connections (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete set null,
  provider text not null check (provider in ('SUPABASE')),
  name text not null,
  project_ref text not null,
  endpoint_url text,
  encrypted_secret text not null,
  secret_hint text,
  access_mode text not null default 'READ_ONLY' check (access_mode in ('READ_ONLY','REMEDIATION')),
  status text not null default 'PENDING' check (status in ('PENDING','CONNECTED','ERROR','DISABLED')),
  last_checked_at timestamptz,
  last_error text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, provider, project_ref)
);

create table if not exists public.database_scans (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  connection_id uuid not null references public.database_connections(id) on delete cascade,
  status text not null default 'RUNNING' check (status in ('RUNNING','COMPLETED','FAILED')),
  security_score integer check (security_score between 0 and 100),
  overall_risk text,
  finding_counts jsonb not null default '{}'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  error_message text,
  created_at timestamptz not null default now()
);

create table if not exists public.database_findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  connection_id uuid not null references public.database_connections(id) on delete cascade,
  scan_id uuid not null references public.database_scans(id) on delete cascade,
  finding_key text not null,
  category text not null,
  severity text not null check (severity in ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  title text not null,
  description text not null,
  impact text,
  evidence jsonb not null default '{}'::jsonb,
  recommended_fix text,
  fix_type text not null default 'MANUAL' check (fix_type in ('MANUAL','ENABLE_RLS','REVOKE_ANON_WRITE','REVOKE_PUBLIC_EXECUTE')),
  status text not null default 'OPEN' check (status in ('OPEN','FIXED','ACCEPTED_RISK','SUPERSEDED')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.remediation_jobs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  connection_id uuid not null references public.database_connections(id) on delete cascade,
  finding_id uuid references public.database_findings(id) on delete set null,
  action_type text not null,
  proposed_change jsonb not null default '{}'::jsonb,
  status text not null default 'PENDING' check (status in ('PENDING','APPROVED','APPLIED','FAILED','CANCELLED')),
  approved_by uuid references auth.users(id) on delete set null,
  applied_by uuid references auth.users(id) on delete set null,
  result jsonb not null default '{}'::jsonb,
  approved_at timestamptz,
  applied_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_database_connections_org on public.database_connections(organization_id);
create index if not exists idx_database_scans_connection_time on public.database_scans(connection_id, created_at desc);
create index if not exists idx_database_findings_connection_status on public.database_findings(connection_id, status, severity);
create index if not exists idx_remediation_jobs_org_time on public.remediation_jobs(organization_id, created_at desc);

alter table public.database_connections enable row level security;
alter table public.database_scans enable row level security;
alter table public.database_findings enable row level security;
alter table public.remediation_jobs enable row level security;

drop policy if exists "database_connections_member_read" on public.database_connections;
create policy "database_connections_member_read" on public.database_connections for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_connections.organization_id and tm.user_id=(select auth.uid())));

drop policy if exists "database_connections_manager_write" on public.database_connections;
create policy "database_connections_manager_write" on public.database_connections for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_connections.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')))
with check (exists(select 1 from public.team_members tm where tm.organization_id=database_connections.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')));

drop policy if exists "database_scans_member_read" on public.database_scans;
create policy "database_scans_member_read" on public.database_scans for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_scans.organization_id and tm.user_id=(select auth.uid())));

drop policy if exists "database_scans_security_write" on public.database_scans;
create policy "database_scans_security_write" on public.database_scans for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_scans.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id=database_scans.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "database_findings_member_read" on public.database_findings;
create policy "database_findings_member_read" on public.database_findings for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_findings.organization_id and tm.user_id=(select auth.uid())));

drop policy if exists "database_findings_security_write" on public.database_findings;
create policy "database_findings_security_write" on public.database_findings for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=database_findings.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')))
with check (exists(select 1 from public.team_members tm where tm.organization_id=database_findings.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

drop policy if exists "remediation_jobs_member_read" on public.remediation_jobs;
create policy "remediation_jobs_member_read" on public.remediation_jobs for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=remediation_jobs.organization_id and tm.user_id=(select auth.uid())));

drop policy if exists "remediation_jobs_manager_write" on public.remediation_jobs;
create policy "remediation_jobs_manager_write" on public.remediation_jobs for all to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=remediation_jobs.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')))
with check (exists(select 1 from public.team_members tm where tm.organization_id=remediation_jobs.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')));
