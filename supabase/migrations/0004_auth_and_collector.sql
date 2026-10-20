-- WebShield production compatibility: auth provisioning + universal collector
-- Keeps website collector keys per tenant and exposes only a constrained ingestion RPC.

alter table public.websites
  add column if not exists collector_key text,
  add column if not exists collector_enabled boolean not null default false,
  add column if not exists last_event_at timestamptz;

update public.websites
set collector_key = encode(gen_random_bytes(24), 'hex')
where collector_key is null or collector_key = '';

alter table public.websites
  alter column collector_key set default encode(gen_random_bytes(24), 'hex'),
  alter column collector_key set not null;

create unique index if not exists idx_websites_collector_key
  on public.websites(collector_key);

create or replace function public.handle_webshield_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_org_id uuid;
  v_plan_id uuid;
  v_name text;
begin
  v_name := coalesce(
    nullif(trim(new.raw_user_meta_data ->> 'display_name'), ''),
    nullif(split_part(coalesce(new.email,''), '@', 1), ''),
    'WebShield User'
  );

  insert into public.users(id, full_name)
  values (new.id, v_name)
  on conflict (id) do update
    set full_name = excluded.full_name,
        updated_at = now();

  insert into public.organizations(name, slug)
  values (
    v_name || ' Workspace',
    'ws-' || replace(substr(new.id::text, 1, 18), '-', '')
  )
  returning id into v_org_id;

  insert into public.team_members(organization_id, user_id, role)
  values (v_org_id, new.id, 'OWNER');

  select id into v_plan_id
  from public.plans
  where code = 'FREE'
  limit 1;

  if v_plan_id is not null then
    insert into public.subscriptions(organization_id, plan_id, status, current_period_start)
    values (v_org_id, v_plan_id, 'ACTIVE', now())
    on conflict (organization_id) do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists on_webshield_auth_user_created on auth.users;
create trigger on_webshield_auth_user_created
after insert on auth.users
for each row execute function public.handle_webshield_new_user();

create or replace function public.webshield_ingest_event(
  p_collector_key text,
  p_origin text,
  p_ip text default null,
  p_country text default null,
  p_city text default null,
  p_device text default null,
  p_browser text default null,
  p_os text default null,
  p_referrer text default null,
  p_url text default null,
  p_visitor_key text default null,
  p_is_bot boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_site public.websites%rowtype;
  v_origin_host text;
  v_expected_host text;
  v_ip inet;
  v_visitor_id uuid;
  v_session_id uuid;
  v_url text;
begin
  if coalesce(trim(p_collector_key), '') = ''
     or coalesce(trim(p_origin), '') = ''
     or coalesce(trim(p_url), '') = ''
     or coalesce(trim(p_visitor_key), '') = '' then
    return jsonb_build_object('ok', false, 'error', 'invalid_payload');
  end if;

  select *
  into v_site
  from public.websites
  where collector_key = p_collector_key
    and collector_enabled = true
  limit 1;

  if v_site.id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_site_key');
  end if;

  v_origin_host := lower(
    split_part(
      split_part(
        regexp_replace(trim(p_origin), '^https?://', '', 'i'),
        '/',
        1
      ),
      ':',
      1
    )
  );
  v_origin_host := regexp_replace(v_origin_host, '^www\.', '', 'i');
  v_expected_host := regexp_replace(lower(v_site.domain), '^www\.', '', 'i');

  if v_origin_host = '' or v_origin_host <> v_expected_host then
    return jsonb_build_object('ok', false, 'error', 'origin_mismatch');
  end if;

  begin
    v_ip := nullif(trim(coalesce(p_ip,'')), '')::inet;
  exception when others then
    v_ip := null;
  end;

  v_url := left(p_url, 2000);

  select id
  into v_visitor_id
  from public.visitors
  where website_id = v_site.id
    and visitor_key = left(p_visitor_key, 128)
  order by last_seen_at desc
  limit 1;

  if v_visitor_id is null then
    insert into public.visitors(
      organization_id, website_id, visitor_key, ip_address,
      country, city, device, browser, operating_system, referrer
    )
    values (
      v_site.organization_id, v_site.id, left(p_visitor_key,128), v_ip,
      nullif(left(coalesce(p_country,''),100),''),
      nullif(left(coalesce(p_city,''),150),''),
      nullif(left(coalesce(p_device,''),80),''),
      nullif(left(coalesce(p_browser,''),80),''),
      nullif(left(coalesce(p_os,''),100),''),
      nullif(left(coalesce(p_referrer,''),1000),'')
    )
    returning id into v_visitor_id;
  else
    update public.visitors
    set ip_address = coalesce(v_ip, ip_address),
        country = coalesce(nullif(left(coalesce(p_country,''),100),''), country),
        city = coalesce(nullif(left(coalesce(p_city,''),150),''), city),
        device = coalesce(nullif(left(coalesce(p_device,''),80),''), device),
        browser = coalesce(nullif(left(coalesce(p_browser,''),80),''), browser),
        operating_system = coalesce(nullif(left(coalesce(p_os,''),100),''), operating_system),
        referrer = coalesce(nullif(left(coalesce(p_referrer,''),1000),''), referrer),
        last_seen_at = now()
    where id = v_visitor_id;
  end if;

  insert into public.visitor_sessions(
    organization_id, website_id, visitor_id, requested_url,
    request_method, risk_score, status, occurred_at
  )
  values (
    v_site.organization_id, v_site.id, v_visitor_id, v_url,
    'GET', case when p_is_bot then 60 else 0 end,
    case when p_is_bot then 'SUSPICIOUS' else 'SAFE' end,
    now()
  )
  returning id into v_session_id;

  if p_is_bot then
    insert into public.threat_events(
      organization_id, website_id, visitor_session_id, type, severity,
      source_ip, target_url, risk_score, status, action_taken, metadata
    )
    values (
      v_site.organization_id, v_site.id, v_session_id, 'BOT_ACTIVITY', 'MEDIUM',
      v_ip, v_url, 60, 'OPEN', 'MONITOR',
      jsonb_build_object('signal','collector_bot_or_automation')
    );
  end if;

  update public.websites
  set last_event_at = now(),
      integration_status = 'COLLECTOR_CONNECTED',
      updated_at = now()
  where id = v_site.id;

  return jsonb_build_object(
    'ok', true,
    'website_id', v_site.id,
    'visitor_id', v_visitor_id,
    'session_id', v_session_id
  );
end;
$$;

revoke all on function public.webshield_ingest_event(text,text,text,text,text,text,text,text,text,text,text,boolean) from public;
grant execute on function public.webshield_ingest_event(text,text,text,text,text,text,text,text,text,text,text,boolean) to anon, authenticated;
