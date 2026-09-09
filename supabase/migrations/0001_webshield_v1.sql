-- WebShield V1 database foundation
-- Demo telemetry is not inserted by this migration. Production data must come from authenticated collectors/providers.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.team_members (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('OWNER','ADMIN','SECURITY_ANALYST','MEMBER','VIEWER')),
  created_at timestamptz not null default now(),
  unique (organization_id,user_id)
);

create table if not exists public.websites (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  domain text not null,
  status text not null default 'PENDING' check (status in ('CONNECTED','PENDING','VERIFICATION_REQUIRED','PROTECTED','ERROR')),
  verification_token_hash text,
  verified_at timestamptz,
  ssl_status text default 'UNKNOWN',
  integration_status text default 'NOT_CONNECTED',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id,domain)
);

create table if not exists public.visitors (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid not null references public.websites(id) on delete cascade,
  visitor_key text not null,
  ip_address inet,
  country text,
  city text,
  device text,
  browser text,
  operating_system text,
  referrer text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists public.visitor_sessions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid not null references public.websites(id) on delete cascade,
  visitor_id uuid references public.visitors(id) on delete set null,
  requested_url text not null,
  request_method text not null default 'GET',
  risk_score integer not null default 0 check (risk_score between 0 and 100),
  status text not null default 'SAFE' check (status in ('SAFE','SUSPICIOUS','THREAT','BLOCKED')),
  occurred_at timestamptz not null default now()
);

create table if not exists public.threat_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid not null references public.websites(id) on delete cascade,
  visitor_session_id uuid references public.visitor_sessions(id) on delete set null,
  type text not null,
  severity text not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  source_ip inet,
  target_url text,
  risk_score integer not null check (risk_score between 0 and 100),
  status text not null default 'OPEN',
  action_taken text,
  metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);

create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete cascade,
  event_type text not null,
  severity text,
  source text not null default 'provider',
  payload jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);

create table if not exists public.firewall_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete cascade,
  name text not null,
  priority integer not null default 100,
  enabled boolean not null default true,
  conditions jsonb not null default '[]'::jsonb,
  action text not null check (action in ('ALLOW','BLOCK','CHALLENGE','RATE_LIMIT')),
  provider_rule_id text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.ip_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete cascade,
  ip_cidr cidr not null,
  action text not null check (action in ('ALLOW','BLOCK','CHALLENGE','RATE_LIMIT')),
  note text,
  created_at timestamptz not null default now()
);

create table if not exists public.country_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete cascade,
  country_code text not null check (char_length(country_code)=2),
  action text not null check (action in ('ALLOW','BLOCK','CHALLENGE','RATE_LIMIT')),
  created_at timestamptz not null default now()
);

create table if not exists public.alerts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  website_id uuid references public.websites(id) on delete cascade,
  type text not null,
  severity text not null,
  title text not null,
  message text,
  acknowledged_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid references auth.users(id) on delete cascade,
  alert_id uuid references public.alerts(id) on delete cascade,
  channel text not null check (channel in ('DASHBOARD','EMAIL','WEBHOOK')),
  status text not null default 'PENDING',
  sent_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  key_prefix text not null,
  key_hash text not null,
  scopes text[] not null default '{}',
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.webhooks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  endpoint_url text not null,
  secret_hash text not null,
  event_types text[] not null default '{}',
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.webhook_logs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  webhook_id uuid not null references public.webhooks(id) on delete cascade,
  event_type text not null,
  response_status integer,
  attempt integer not null default 1,
  delivered_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.plans (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code in ('FREE','STARTER','BUSINESS','ENTERPRISE')),
  name text not null,
  website_limit integer,
  monthly_visitor_limit bigint,
  security_event_limit bigint,
  retention_days integer,
  api_access boolean not null default false,
  reports_access boolean not null default true,
  team_member_limit integer,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null unique references public.organizations(id) on delete cascade,
  plan_id uuid not null references public.plans(id),
  provider text,
  provider_subscription_id text,
  status text not null default 'ACTIVE',
  current_period_start timestamptz,
  current_period_end timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  subscription_id uuid references public.subscriptions(id) on delete set null,
  provider_invoice_id text,
  amount_minor bigint not null default 0,
  currency text not null default 'INR',
  status text not null default 'DRAFT',
  invoice_url text,
  issued_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations(id) on delete set null,
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  resource_type text not null,
  resource_id text,
  ip_address inet,
  result text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  created_by uuid references auth.users(id) on delete set null,
  subject text not null,
  description text,
  priority text not null default 'MEDIUM',
  status text not null default 'OPEN',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_team_members_user on public.team_members(user_id);
create index if not exists idx_websites_org on public.websites(organization_id);
create index if not exists idx_visitors_site_time on public.visitors(website_id,last_seen_at desc);
create index if not exists idx_sessions_site_time on public.visitor_sessions(website_id,occurred_at desc);
create index if not exists idx_threats_site_time on public.threat_events(website_id,occurred_at desc);
create index if not exists idx_security_events_org_time on public.security_events(organization_id,occurred_at desc);
create index if not exists idx_audit_org_time on public.audit_logs(organization_id,created_at desc);

-- Enable RLS on every exposed public table.
alter table public.organizations enable row level security;
alter table public.users enable row level security;
alter table public.team_members enable row level security;
alter table public.websites enable row level security;
alter table public.visitors enable row level security;
alter table public.visitor_sessions enable row level security;
alter table public.threat_events enable row level security;
alter table public.security_events enable row level security;
alter table public.firewall_rules enable row level security;
alter table public.ip_rules enable row level security;
alter table public.country_rules enable row level security;
alter table public.alerts enable row level security;
alter table public.notifications enable row level security;
alter table public.api_keys enable row level security;
alter table public.webhooks enable row level security;
alter table public.webhook_logs enable row level security;
alter table public.plans enable row level security;
alter table public.subscriptions enable row level security;
alter table public.invoices enable row level security;
alter table public.audit_logs enable row level security;
alter table public.support_tickets enable row level security;

-- User/profile access.
create policy "users_read_self" on public.users for select to authenticated using ((select auth.uid()) = id);
create policy "users_update_self" on public.users for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
create policy "members_read_own_memberships" on public.team_members for select to authenticated using ((select auth.uid()) = user_id);

-- Organizations can be read by their members.
create policy "org_members_read" on public.organizations for select to authenticated
using (exists(select 1 from public.team_members tm where tm.organization_id=id and tm.user_id=(select auth.uid())));

-- Tenant isolation policies. team_members itself only exposes the caller's membership rows,
-- so these EXISTS checks stay scoped to organizations the caller actually belongs to.
create policy "websites_member_read" on public.websites for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=websites.organization_id and tm.user_id=(select auth.uid())));
create policy "websites_manager_write" on public.websites for all to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=websites.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST'))) with check (exists(select 1 from public.team_members tm where tm.organization_id=websites.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

create policy "visitors_member_read" on public.visitors for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=visitors.organization_id and tm.user_id=(select auth.uid())));
create policy "sessions_member_read" on public.visitor_sessions for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=visitor_sessions.organization_id and tm.user_id=(select auth.uid())));
create policy "threats_member_read" on public.threat_events for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=threat_events.organization_id and tm.user_id=(select auth.uid())));
create policy "events_member_read" on public.security_events for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=security_events.organization_id and tm.user_id=(select auth.uid())));

create policy "firewall_member_read" on public.firewall_rules for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=firewall_rules.organization_id and tm.user_id=(select auth.uid())));
create policy "firewall_manager_write" on public.firewall_rules for all to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=firewall_rules.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST'))) with check (exists(select 1 from public.team_members tm where tm.organization_id=firewall_rules.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));
create policy "ip_rules_member_read" on public.ip_rules for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=ip_rules.organization_id and tm.user_id=(select auth.uid())));
create policy "country_rules_member_read" on public.country_rules for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=country_rules.organization_id and tm.user_id=(select auth.uid())));

create policy "alerts_member_read" on public.alerts for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=alerts.organization_id and tm.user_id=(select auth.uid())));
create policy "notifications_read_self" on public.notifications for select to authenticated using ((select auth.uid())=user_id);
create policy "api_keys_manager_read" on public.api_keys for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=api_keys.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')));
create policy "webhooks_manager_read" on public.webhooks for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=webhooks.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN')));
create policy "webhook_logs_manager_read" on public.webhook_logs for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=webhook_logs.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));

create policy "plans_authenticated_read" on public.plans for select to authenticated using (active=true);
create policy "subscriptions_member_read" on public.subscriptions for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=subscriptions.organization_id and tm.user_id=(select auth.uid())));
create policy "invoices_member_read" on public.invoices for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=invoices.organization_id and tm.user_id=(select auth.uid())));
create policy "audit_manager_read" on public.audit_logs for select to authenticated using (organization_id is not null and exists(select 1 from public.team_members tm where tm.organization_id=audit_logs.organization_id and tm.user_id=(select auth.uid()) and tm.role in ('OWNER','ADMIN','SECURITY_ANALYST')));
create policy "tickets_member_read" on public.support_tickets for select to authenticated using (exists(select 1 from public.team_members tm where tm.organization_id=support_tickets.organization_id and tm.user_id=(select auth.uid())));
create policy "tickets_member_insert" on public.support_tickets for insert to authenticated with check (created_by=(select auth.uid()) and exists(select 1 from public.team_members tm where tm.organization_id=support_tickets.organization_id and tm.user_id=(select auth.uid())));

-- Seed plan definitions only; no fake invoices/subscriptions/telemetry.
insert into public.plans(code,name,website_limit,monthly_visitor_limit,security_event_limit,retention_days,reports_access,api_access,team_member_limit)
values
('FREE','Free',1,10000,10000,7,true,false,1),
('STARTER','Starter',3,100000,100000,30,true,false,3),
('BUSINESS','Business',10,1000000,1000000,90,true,true,10),
('ENTERPRISE','Enterprise',null,null,null,null,true,true,null)
on conflict (code) do nothing;
