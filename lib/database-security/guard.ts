// WebShield Data Guard.
//
// Installs a small change-capture trigger inside a monitored Postgres/Supabase
// database. Every INSERT / UPDATE / DELETE / TRUNCATE on a watched table is
// recorded in webshield_guard.change_log with WHO made the change (API role,
// auth user id, direct database user, client IP) and WHICH columns changed.
// Row contents are never copied, only the primary key and column names.
//
// WebShield then polls the log with a read-only query and classifies each
// change. Unauthenticated writes, direct database writes outside the API,
// privilege/credential edits and mass deletes become alerts.
//
// This file is intentionally free of Node/Next imports so it can be unit tested.

export type GuardSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type GuardConfig = {
  /** Tables (schema.table) where anonymous INSERTs are expected, e.g. a public lead form. */
  anonInsertTables: string[];
  /** Database users trusted to write directly (e.g. a migration user or cron owner). */
  trustedDbUsers: string[];
  massDeleteThreshold?: number;
  massUpdateThreshold?: number;
};

export type GuardChange = {
  id: number | string;
  occurred_at: string;
  table_schema: string;
  table_name: string;
  operation: string;
  db_user: string | null;
  jwt_role: string | null;
  jwt_sub: string | null;
  client_ip: string | null;
  row_pk: string | null;
  changed_columns: string[] | string | null;
};

export type GuardReason = { code: string; severity: GuardSeverity; message: string };

export type ClassifiedChange = GuardChange & {
  sourceId: number;
  table: string;
  columns: string[];
  actor: string;
  suspicious: boolean;
  severity: GuardSeverity;
  reasons: GuardReason[];
};

export type GuardAlert = {
  dedupeKey: string;
  code: string;
  severity: GuardSeverity;
  table: string;
  title: string;
  message: string;
  count: number;
  actors: string[];
  ips: string[];
  firstSeen: string;
  lastSeen: string;
};

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const SEVERITY_ORDER: GuardSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
// Platform roles that maintain their own schemas. Writes from them into watched
// application tables are unusual but expected during platform operations.
const PLATFORM_DB_USERS = ["supabase_admin", "supabase_auth_admin", "supabase_storage_admin", "supabase_realtime_admin", "supabase_replication_admin"];
const BACKEND_API_ROLE = ["service", "role"].join("_");
const PRIVILEGE_COLUMNS = new Set([
  "role", "roles", "user_role", "app_role", "is_admin", "admin", "is_super_admin", "is_superuser", "superuser",
  "permissions", "permission", "access_level", "privileges", "scopes",
  "password", "password_hash", "encrypted_password", "pin", "otp", "otp_hash",
  "api_key", "api_secret", "secret", "token", "access_token", "refresh_token"
]);

export const GUARD_SCHEMA = "webshield_guard";
export const GUARD_POLL_LIMIT = 500;

export function maxSeverity(values: GuardSeverity[]): GuardSeverity {
  return values.reduce<GuardSeverity>((best, value) => SEVERITY_ORDER.indexOf(value) > SEVERITY_ORDER.indexOf(best) ? value : best, "INFO");
}

export function severityAtLeast(value: string, threshold: string) {
  return SEVERITY_ORDER.indexOf(value as GuardSeverity) >= SEVERITY_ORDER.indexOf(threshold as GuardSeverity);
}

/** Validates "table" or "schema.table" and returns { schema, table, key }. */
export function parseTableName(value: string) {
  const raw = String(value || "").trim();
  const parts = raw.split(".");
  const [schema, table] = parts.length === 2 ? parts : ["public", parts[0]];
  if (parts.length > 2 || !IDENT.test(schema) || !IDENT.test(table)) throw new Error(`Invalid table name: ${raw.slice(0, 80)}`);
  if (["auth", "storage", "pg_catalog", "information_schema", GUARD_SCHEMA].includes(schema)) throw new Error(`Schema ${schema} cannot be watched.`);
  return { schema, table, key: `${schema}.${table}` };
}

export function normalizeTableList(values: unknown, max = 200) {
  const list = Array.isArray(values) ? values : String(values || "").split(/[\s,]+/);
  const seen = new Set<string>();
  for (const value of list) {
    if (!String(value || "").trim()) continue;
    seen.add(parseTableName(String(value)).key);
    if (seen.size > max) throw new Error(`At most ${max} tables can be watched.`);
  }
  return [...seen].sort();
}

export function normalizeDbUsers(values: unknown) {
  const list = Array.isArray(values) ? values : String(values || "").split(/[\s,]+/);
  return [...new Set(list.map(v => String(v || "").trim()).filter(Boolean).map(v => {
    if (!IDENT.test(v)) throw new Error(`Invalid database user: ${v.slice(0, 64)}`);
    return v;
  }))].sort();
}

function q(identifier: string) {
  if (!IDENT.test(identifier)) throw new Error("Invalid identifier.");
  return '"' + identifier + '"';
}

const CAPTURE_FUNCTION_SQL = `
create schema if not exists ${GUARD_SCHEMA};
revoke all on schema ${GUARD_SCHEMA} from public;
do $grant$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on schema ${GUARD_SCHEMA} from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on schema ${GUARD_SCHEMA} from authenticated'; end if;
end $grant$;

create table if not exists ${GUARD_SCHEMA}.change_log (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default clock_timestamp(),
  table_schema text not null,
  table_name text not null,
  operation text not null,
  db_user text,
  jwt_role text,
  jwt_sub text,
  client_ip text,
  row_pk text,
  changed_columns text[] not null default '{}'
);
create index if not exists change_log_occurred_at on ${GUARD_SCHEMA}.change_log(occurred_at);
-- Not exposed through the Data API: no grants for public/anon/authenticated.
revoke all on ${GUARD_SCHEMA}.change_log from public;
do $grant2$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on ${GUARD_SCHEMA}.change_log from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on ${GUARD_SCHEMA}.change_log from authenticated'; end if;
end $grant2$;

create or replace function ${GUARD_SCHEMA}.capture()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $fn$
declare
  v_claims jsonb;
  v_headers jsonb;
  v_new jsonb;
  v_old jsonb;
  v_changed text[] := '{}';
  v_role text;
  v_ip text;
begin
  begin v_claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb; exception when others then v_claims := null; end;
  begin v_headers := nullif(current_setting('request.headers', true), '')::jsonb; exception when others then v_headers := null; end;

  -- SET ROLE (used by the Data API) survives SECURITY DEFINER; otherwise use the login user.
  v_role := nullif(current_setting('role', true), 'none');
  v_ip := coalesce(
    nullif(split_part(coalesce(v_headers ->> 'x-forwarded-for', ''), ',', 1), ''),
    v_headers ->> 'cf-connecting-ip',
    v_headers ->> 'x-real-ip',
    host(inet_client_addr())
  );

  if tg_level = 'ROW' then
    if tg_op <> 'DELETE' then v_new := to_jsonb(new); end if;
    if tg_op <> 'INSERT' then v_old := to_jsonb(old); end if;
    if tg_op = 'UPDATE' then
      select coalesce(array_agg(n.key order by n.key), '{}') into v_changed
      from jsonb_each(v_new) n
      where n.value is distinct from (v_old -> n.key);
      if cardinality(v_changed) = 0 then return null; end if;
    end if;
  end if;

  insert into ${GUARD_SCHEMA}.change_log(table_schema, table_name, operation, db_user, jwt_role, jwt_sub, client_ip, row_pk, changed_columns)
  values (
    tg_table_schema,
    tg_table_name,
    tg_op,
    left(coalesce(v_role, session_user::text), 128),
    left(v_claims ->> 'role', 64),
    left(v_claims ->> 'sub', 128),
    left(v_ip, 64),
    left(coalesce(v_new, v_old) ->> 'id', 128),
    v_changed
  );

  -- Keep 30 days of history without needing pg_cron.
  if random() < 0.0005 then
    delete from ${GUARD_SCHEMA}.change_log where occurred_at < now() - interval '30 days';
  end if;
  return null;
exception when others then
  -- Monitoring must never break the application's write.
  return null;
end;
$fn$;
revoke all on function ${GUARD_SCHEMA}.capture() from public;
`;

const DROP_ALL_TRIGGERS_SQL = `
do $drop$
declare r record;
begin
  for r in
    select distinct t.tgrelid::regclass as rel
    from pg_trigger t
    where t.tgname in ('webshield_guard_capture', 'webshield_guard_truncate') and not t.tgisinternal
  loop
    execute format('drop trigger if exists webshield_guard_capture on %s', r.rel);
    execute format('drop trigger if exists webshield_guard_truncate on %s', r.rel);
  end loop;
end $drop$;
`;

/** SQL that installs (or re-syncs) Data Guard on exactly the given tables. */
export function guardInstallSql(tables: string[]) {
  const list = normalizeTableList(tables);
  if (!list.length) throw new Error("Select at least one table to watch.");
  const attach = list.map(key => {
    const { schema, table } = parseTableName(key);
    const rel = `${q(schema)}.${q(table)}`;
    return `create trigger webshield_guard_capture after insert or update or delete on ${rel} for each row execute function ${GUARD_SCHEMA}.capture();
create trigger webshield_guard_truncate after truncate on ${rel} for each statement execute function ${GUARD_SCHEMA}.capture();`;
  }).join("\n");
  return `${CAPTURE_FUNCTION_SQL}\n${DROP_ALL_TRIGGERS_SQL}\n${attach}`;
}

export function guardUninstallSql() {
  return `${DROP_ALL_TRIGGERS_SQL}\ndrop schema if exists ${GUARD_SCHEMA} cascade;`;
}

export function guardStatusSql() {
  return `select
  to_regclass('${GUARD_SCHEMA}.change_log') is not null as installed,
  coalesce((
    select array_agg(distinct n.nspname || '.' || c.relname order by n.nspname || '.' || c.relname)
    from pg_trigger t join pg_class c on c.oid = t.tgrelid join pg_namespace n on n.oid = c.relnamespace
    where t.tgname = 'webshield_guard_capture' and not t.tgisinternal
  ), '{}') as watched_tables;`;
}

export function guardPollSql(cursor: number, limit = GUARD_POLL_LIMIT) {
  const after = Math.max(0, Math.floor(Number(cursor) || 0));
  const size = Math.max(1, Math.min(GUARD_POLL_LIMIT, Math.floor(limit)));
  return `select id, occurred_at, table_schema, table_name, operation, db_user, jwt_role, jwt_sub, client_ip, row_pk, changed_columns
from ${GUARD_SCHEMA}.change_log
where id > ${after}
order by id asc
limit ${size};`;
}

export const LIST_TABLES_SQL = `
select n.nspname as schema_name, c.relname as table_name, c.relrowsecurity as rls_enabled,
  coalesce(s.n_live_tup, 0)::bigint as approx_rows
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
left join pg_catalog.pg_stat_user_tables s on s.relid = c.oid
where c.relkind in ('r','p')
  and n.nspname not in ('pg_catalog','information_schema','auth','storage','realtime','supabase_functions','extensions','graphql','graphql_public','pgsodium','pgsodium_masks','vault','net','cron','supabase_migrations','pgbouncer','${GUARD_SCHEMA}')
  and n.nspname not like 'pg_%'
order by n.nspname, c.relname;`;

const SENSITIVE_TABLE = /(user|profile|member|role|permission|admin|account|customer|lead|payment|invoice|payout|commission|finance|ledger|transaction|order|subscription|session|token|key|secret|kyc|document|credit|loan)/i;

/** Suggests which tables to watch first: sensitive business tables. */
export function suggestGuardTables(rows: Array<{ schema_name?: unknown; table_name?: unknown }>, max = 40) {
  return rows
    .map(row => `${String(row.schema_name || "public")}.${String(row.table_name || "")}`)
    .filter(key => { try { parseTableName(key); return SENSITIVE_TABLE.test(key); } catch { return false; } })
    .slice(0, max);
}

function columnsOf(value: GuardChange["changed_columns"]) {
  if (Array.isArray(value)) return value.map(String);
  const raw = String(value || "").replace(/^\{|\}$/g, "");
  return raw ? raw.split(",").map(x => x.replace(/^"|"$/g, "").trim()).filter(Boolean) : [];
}

function roleOf(change: GuardChange) {
  return (change.jwt_role || "").toLowerCase() || null;
}

/** Classifies a batch of captured changes. Pure function. */
export function classifyChanges(changes: GuardChange[], config: GuardConfig): ClassifiedChange[] {
  const anonInsert = new Set(config.anonInsertTables.map(x => { try { return parseTableName(x).key; } catch { return ""; } }));
  const trusted = new Set([...PLATFORM_DB_USERS, ...config.trustedDbUsers]);
  const massDelete = config.massDeleteThreshold ?? 25;
  const massUpdate = config.massUpdateThreshold ?? 200;

  const base = changes.map(change => {
    const table = `${change.table_schema}.${change.table_name}`;
    const columns = columnsOf(change.changed_columns);
    const jwtRole = roleOf(change);
    const dbUser = (change.db_user || "").toLowerCase();
    const op = String(change.operation || "").toUpperCase();
    const actor = change.jwt_sub ? `user:${change.jwt_sub}` : jwtRole ? `role:${jwtRole}` : `db:${dbUser || "unknown"}`;
    const reasons: GuardReason[] = [];
    const isAnon = jwtRole === "anon" || (!jwtRole && dbUser === "anon");
    const isBackend = jwtRole === BACKEND_API_ROLE || (!jwtRole && dbUser === BACKEND_API_ROLE);
    const isApiUser = jwtRole === "authenticated" || (!jwtRole && dbUser === "authenticated");
    const isDirect = !jwtRole && !isAnon && !isBackend && !isApiUser;

    if (op === "TRUNCATE") {
      reasons.push({ code: "TRUNCATE", severity: "CRITICAL", message: `Table ${table} was truncated (all rows removed).` });
    }

    if (isAnon) {
      if (op === "INSERT" && !anonInsert.has(table)) {
        reasons.push({ code: "ANON_WRITE", severity: "MEDIUM", message: `Insert into ${table} without login (anon API key).` });
      } else if (op === "UPDATE" || op === "DELETE") {
        reasons.push({ code: "ANON_WRITE", severity: "HIGH", message: `${op} on ${table} without login (anon API key).` });
      }
    }

    if (isDirect && !trusted.has(dbUser)) {
      reasons.push({
        code: "DIRECT_DB_WRITE",
        severity: op === "DELETE" || op === "TRUNCATE" ? "HIGH" : "MEDIUM",
        message: `${op} on ${table} by database user "${dbUser || "unknown"}" outside the application API (SQL editor, direct connection or scheduled job).`
      });
    }

    if (op === "UPDATE" && !isBackend && !(isDirect && trusted.has(dbUser))) {
      const sensitive = columns.filter(c => PRIVILEGE_COLUMNS.has(c.toLowerCase()));
      if (sensitive.length) {
        reasons.push({ code: "PRIVILEGE_CHANGE", severity: "HIGH", message: `Privilege or credential field changed on ${table}: ${sensitive.join(", ")}.` });
      }
    }

    return { ...change, sourceId: Number(change.id), table, columns, actor, op, reasons };
  });

  // Mass operations: same actor, table and operation inside the batch.
  const groups = new Map<string, typeof base>();
  for (const item of base) {
    if (item.op !== "DELETE" && item.op !== "UPDATE") continue;
    const key = `${item.table}|${item.op}|${item.actor}`;
    groups.set(key, [...(groups.get(key) || []), item]);
  }
  for (const [key, items] of groups) {
    const [table, op, actor] = key.split("|");
    if (op === "DELETE" && items.length >= massDelete) {
      for (const item of items) item.reasons.push({ code: "MASS_DELETE", severity: "CRITICAL", message: `${items.length} rows deleted from ${table} by ${actor} in one monitoring window.` });
    }
    if (op === "UPDATE" && items.length >= massUpdate) {
      for (const item of items) item.reasons.push({ code: "MASS_UPDATE", severity: "HIGH", message: `${items.length} rows updated in ${table} by ${actor} in one monitoring window.` });
    }
  }

  return base.map(({ op: _op, ...item }) => ({
    ...item,
    suspicious: item.reasons.length > 0,
    severity: item.reasons.length ? maxSeverity(item.reasons.map(r => r.severity)) : "INFO"
  }));
}

/** Groups suspicious changes into one alert per (rule, table). */
export function buildGuardAlerts(connectionId: string, connectionName: string, changes: ClassifiedChange[]): GuardAlert[] {
  const groups = new Map<string, { reason: GuardReason; table: string; items: ClassifiedChange[] }>();
  for (const change of changes) {
    for (const reason of change.reasons) {
      const key = `${reason.code}|${change.table}`;
      const group = groups.get(key) || { reason, table: change.table, items: [] };
      if (severityAtLeast(reason.severity, group.reason.severity)) group.reason = reason;
      group.items.push(change);
      groups.set(key, group);
    }
  }
  const titles: Record<string, string> = {
    ANON_WRITE: "Database write without login",
    DIRECT_DB_WRITE: "Direct database change outside the app",
    PRIVILEGE_CHANGE: "Privilege or credential field changed",
    MASS_DELETE: "Mass deletion detected",
    MASS_UPDATE: "Mass update detected",
    TRUNCATE: "Table truncated"
  };
  return [...groups.values()].map(({ reason, table, items }) => {
    const unique = new Map(items.map(i => [i.sourceId, i]));
    const rows = [...unique.values()];
    const actors = [...new Set(rows.map(r => r.actor))].slice(0, 5);
    const ips = [...new Set(rows.map(r => r.client_ip).filter((x): x is string => Boolean(x)))].slice(0, 5);
    const times = rows.map(r => r.occurred_at).sort();
    return {
      dedupeKey: `guard:${connectionId}:${reason.code}:${table}`,
      code: reason.code,
      severity: reason.severity,
      table,
      title: `${titles[reason.code] || "Suspicious database activity"} · ${table}`,
      message: `${connectionName}: ${reason.message} ${rows.length} change(s). Actor: ${actors.join(", ")}${ips.length ? ` · IP: ${ips.join(", ")}` : ""}.`,
      count: rows.length,
      actors,
      ips,
      firstSeen: times[0],
      lastSeen: times[times.length - 1]
    };
  });
}
