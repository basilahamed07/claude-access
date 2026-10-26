-- AgentShield initial schema (db spec §B). Runs as the owner/superuser. Idempotent where practical.
create extension if not exists citext;

-- ── roles (login roles are created by the operator and granted one of these) ────────────
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'agentshield_owner') then create role agentshield_owner nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'agentshield_app') then create role agentshield_app nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'agentshield_worker') then create role agentshield_worker nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'agentshield_retention') then create role agentshield_retention nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'agentshield_readonly') then create role agentshield_readonly nologin; end if;
end $$;

create schema if not exists private;
revoke all on schema public from public;
grant usage on schema public to agentshield_app, agentshield_worker, agentshield_retention, agentshield_readonly, agentshield_owner;
grant create on schema public to agentshield_owner;
grant usage on schema private to agentshield_app, agentshield_worker, agentshield_retention, agentshield_owner;
grant create on schema private to agentshield_owner;

-- uuidv7(): built into PostgreSQL 18; a compatible fallback is created for older servers.
do $$
begin
  if not exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                 where p.proname = 'uuidv7' and n.nspname in ('pg_catalog', 'public')) then
    execute $f$
      create function public.uuidv7() returns uuid language plpgsql volatile as $body$
      declare
        ts_ms bigint := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
        rnd bytea := uuid_send(gen_random_uuid());
        b bytea;
      begin
        b := decode(lpad(to_hex(ts_ms), 12, '0'), 'hex') || substring(rnd from 7 for 10);
        b := set_byte(b, 6, (get_byte(b, 6) & 15) | 112);
        b := set_byte(b, 8, (get_byte(b, 8) & 63) | 128);
        return encode(b, 'hex')::uuid;
      end $body$;
    $f$;
  end if;
end $$;
grant execute on function public.uuidv7() to public;

-- ── core tables ────────────────────────────────────────────────────────────────────────
create table if not exists tenants (
  id          uuid primary key default uuidv7(),
  name        text not null check (length(name) between 2 and 100),
  slug        text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  settings    jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

create table if not exists users (
  id            uuid primary key default uuidv7(),
  tenant_id     uuid not null references tenants(id),
  email         citext not null unique,
  password_hash text not null,
  role          text not null check (role in ('admin','analyst','viewer')),
  failed_logins int  not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  disabled_at   timestamptz
);
create index if not exists users_tenant_idx on users (tenant_id);

create table if not exists user_tokens (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid not null references tenants(id),
  user_id     uuid not null references users(id),
  prefix      text not null unique,
  token_hash  bytea not null,
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz
);
create index if not exists user_tokens_tenant_user_idx on user_tokens (tenant_id, user_id);

create table if not exists upstreams (
  id             uuid primary key default uuidv7(),
  tenant_id      uuid not null references tenants(id),
  name           text not null,
  kind           text not null check (kind in ('anthropic','openai','openai_compat')),
  base_url       text not null,
  key_ciphertext bytea,
  model_map      jsonb not null default '{}'::jsonb,
  judge_model    text,
  created_at     timestamptz not null default now(),
  unique (tenant_id, name)
);

create table if not exists agents (
  id                    uuid primary key default uuidv7(),
  tenant_id             uuid not null references tenants(id),
  slug                  text not null check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name                  text not null,
  owner                 text not null,
  purpose               text not null default '',
  risk_tier             text not null check (risk_tier in ('low','medium','high')),
  mode                  text not null default 'monitor' check (mode in ('enforce','monitor')),
  key_mode              text not null default 'stored' check (key_mode in ('stored','passthrough')),
  upstream_id           uuid references upstreams(id),
  active_policy_version int,
  status                text not null default 'active' check (status in ('active','suspended')),
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  unique (tenant_id, slug)
);
create index if not exists agents_tenant_upstream_idx on agents (tenant_id, upstream_id);

create table if not exists agent_keys (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid not null references tenants(id),
  agent_id    uuid not null references agents(id),
  prefix      text not null unique,
  key_hash    bytea not null,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);
create index if not exists agent_keys_tenant_agent_idx on agent_keys (tenant_id, agent_id);

create table if not exists policy_versions (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid not null references tenants(id),
  agent_id    uuid not null references agents(id),
  version     int  not null check (version > 0),
  yaml        text not null,
  parsed      jsonb not null,
  sha256      bytea not null,
  created_by  uuid not null references users(id),
  created_at  timestamptz not null default now(),
  unique (tenant_id, agent_id, version)
);
create index if not exists policy_versions_agent_idx on policy_versions (agent_id);
create index if not exists policy_versions_created_by_idx on policy_versions (created_by);

create table if not exists sessions (
  id           uuid primary key default uuidv7(),
  tenant_id    uuid not null references tenants(id),
  agent_id     uuid not null references agents(id),
  session_key  text not null check (length(session_key) <= 200),
  user_request text,
  end_user     text,
  risk_score   real not null default 0 check (risk_score between 0 and 1),
  started_at   timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (tenant_id, agent_id, session_key)
);
create index if not exists sessions_agent_idx on sessions (agent_id, last_seen_at desc);
create index if not exists sessions_tenant_last_seen_idx on sessions (tenant_id, last_seen_at desc);

create table if not exists approvals (
  id               uuid primary key default uuidv7(),
  tenant_id        uuid not null references tenants(id),
  agent_id         uuid not null references agents(id),
  session_id       uuid not null references sessions(id),
  trace_id         text not null,
  tool             text not null,
  args_hash        text not null,
  args_redacted    jsonb not null,
  rule_id          text not null,
  status           text not null default 'pending' check (status in ('pending','approved','denied','expired')),
  decided_by       uuid references users(id),
  decided_at       timestamptz,
  note             text,
  expires_at       timestamptz not null,
  created_at       timestamptz not null default now(),
  check ((status = 'pending') = (decided_at is null))
);
create index if not exists approvals_tenant_agent_idx on approvals (tenant_id, agent_id);
create index if not exists approvals_session_idx on approvals (session_id);
create index if not exists approvals_decided_by_idx on approvals (decided_by);
create index if not exists approvals_pending_expiry_idx on approvals (expires_at) where status = 'pending';

create table if not exists budget_counters (
  tenant_id      uuid not null references tenants(id),
  agent_id       uuid not null references agents(id),
  day            date not null,
  tokens         bigint not null default 0,
  cost_micro_usd bigint not null default 0,
  calls          bigint not null default 0,
  primary key (tenant_id, agent_id, day)
);
create index if not exists budget_counters_agent_idx on budget_counters (agent_id);

create table if not exists incidents (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid not null references tenants(id),
  session_id  uuid not null references sessions(id),
  title       text not null,
  severity    text not null check (severity in ('low','medium','high','critical')),
  status      text not null default 'open' check (status in ('open','investigating','closed')),
  created_by  uuid not null references users(id),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists incidents_tenant_status_idx on incidents (tenant_id, status, created_at desc);
create index if not exists incidents_session_idx on incidents (session_id);
create index if not exists incidents_created_by_idx on incidents (created_by);

create table if not exists scan_rule_sets (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid references tenants(id),
  version     int not null,
  yaml        text not null,
  sha256      bytea not null,
  active      boolean not null default false,
  created_at  timestamptz not null default now(),
  unique nulls not distinct (tenant_id, version)
);

-- ── later-stage tables (created now so contracts are stable; empty in v1) ───────────────
create table if not exists mcp_servers (
  id              uuid primary key default uuidv7(),
  tenant_id       uuid not null references tenants(id),
  name            text not null,
  ref             text not null,
  pinned_version  text not null,
  fingerprint     bytea,
  verdict         text not null default 'pending' check (verdict in ('pending','approved','approved_with_limits','rejected','suspended')),
  owner           text not null,
  report          jsonb,
  created_at      timestamptz not null default now(),
  unique (tenant_id, name)
);
create table if not exists ai_tools_seen (
  id              uuid primary key default uuidv7(),
  tenant_id       uuid not null references tenants(id),
  domain          text not null,
  vendor          text,
  classification  text not null check (classification in ('approved','tolerated','blocked','unknown')),
  team            text,
  first_seen      timestamptz not null,
  last_seen       timestamptz not null,
  unique nulls not distinct (tenant_id, domain, team)
);

-- ── audit (append-only, partitioned by month) ────────────────────────────────────────────
create table if not exists audit_events (
  tenant_id         uuid not null,
  seq               bigint not null,
  ts                timestamptz not null,
  schema            text not null default 'agentshield.event/1',
  id                text not null,
  trace_id          text not null,
  session_id        uuid,
  agent_slug        text,
  end_user          text,
  parent_id         text,
  module            text not null check (module in ('gateway','policy','injection','mcp','shadow','approval','audit')),
  type              text not null,
  decision          text check (decision in ('allow','block','ask')),
  rule_id           text,
  reason            text,
  severity          text not null check (severity in ('info','low','medium','high','critical')),
  summary           text not null,
  payload_sha256    bytea not null,
  payload_truncated boolean not null default false,
  prev_hash         bytea not null,
  hash              bytea not null,
  otel_span_id      text,
  primary key (tenant_id, seq, ts)
) partition by range (ts);
create unique index if not exists audit_events_event_id_idx on audit_events (tenant_id, id, ts);
create index if not exists audit_events_trace_idx on audit_events (tenant_id, trace_id);
create index if not exists audit_events_session_idx on audit_events (tenant_id, session_id, seq);
create index if not exists audit_events_filter_idx on audit_events (tenant_id, ts desc, seq desc);
create index if not exists audit_events_decision_idx on audit_events (tenant_id, decision, ts desc) where decision is not null;
create index if not exists audit_events_user_idx on audit_events (tenant_id, end_user, ts desc) where end_user is not null;

create table if not exists audit_payloads (
  tenant_id  uuid not null,
  seq        bigint not null,
  ts         timestamptz not null,
  session_id uuid,
  payload    jsonb not null,
  primary key (tenant_id, seq, ts)
) partition by range (ts);

create table if not exists audit_events_archive (like audit_events including defaults);
alter table audit_events_archive add primary key (tenant_id, seq, ts);
create table if not exists audit_payloads_archive (like audit_payloads including defaults);
alter table audit_payloads_archive add primary key (tenant_id, seq, ts);

create table if not exists audit_chain_heads (
  tenant_id uuid primary key references tenants(id),
  last_seq  bigint not null,
  last_hash bytea not null
);

-- ── triggers ───────────────────────────────────────────────────────────────────────────
create or replace function private.reject_mutation() returns trigger language plpgsql as $$
begin
  raise exception 'append-only table %', tg_table_name using errcode = '42501';
end $$;

create or replace function private.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;

drop trigger if exists audit_events_no_mutation on audit_events;
create trigger audit_events_no_mutation before update or delete on audit_events
  for each row execute function private.reject_mutation();
drop trigger if exists audit_events_archive_no_mutation on audit_events_archive;
create trigger audit_events_archive_no_mutation before update or delete on audit_events_archive
  for each row execute function private.reject_mutation();
drop trigger if exists policy_versions_no_mutation on policy_versions;
create trigger policy_versions_no_mutation before update or delete on policy_versions
  for each row execute function private.reject_mutation();
drop trigger if exists agents_touch on agents;
create trigger agents_touch before update on agents for each row execute function private.touch_updated_at();
drop trigger if exists incidents_touch on incidents;
create trigger incidents_touch before update on incidents for each row execute function private.touch_updated_at();

-- ── partitions ─────────────────────────────────────────────────────────────────────────
create or replace function private.ensure_audit_partitions(months_ahead int default 3) returns int
language plpgsql as $$
declare m date; n int := 0; nm text;
begin
  for i in -1..months_ahead loop
    m := (date_trunc('month', now() at time zone 'utc') + make_interval(months => i))::date;
    nm := to_char(m, 'YYYY_MM');
    if to_regclass('audit_events_' || nm) is null then
      execute format('create table %I partition of audit_events for values from (%L) to (%L)',
                     'audit_events_' || nm, m::timestamptz, (m + interval '1 month')::timestamptz);
      n := n + 1;
    end if;
    if to_regclass('audit_payloads_' || nm) is null then
      execute format('create table %I partition of audit_payloads for values from (%L) to (%L)',
                     'audit_payloads_' || nm, m::timestamptz, (m + interval '1 month')::timestamptz);
      n := n + 1;
    end if;
  end loop;
  if to_regclass('audit_events_default') is null then
    execute 'create table audit_events_default partition of audit_events default'; n := n + 1;
  end if;
  if to_regclass('audit_payloads_default') is null then
    execute 'create table audit_payloads_default partition of audit_payloads default'; n := n + 1;
  end if;
  return n;
end $$;
select private.ensure_audit_partitions(3);

-- ── row level security ───────────────────────────────────────────────────────────────────
do $$
declare t text;
begin
  foreach t in array array['users','user_tokens','upstreams','agents','agent_keys','policy_versions',
    'sessions','approvals','budget_counters','incidents','mcp_servers','ai_tools_seen',
    'audit_events','audit_payloads','audit_events_archive','audit_payloads_archive','audit_chain_heads']
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format($p$create policy tenant_isolation on %I
        using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
        with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))$p$, t);
    execute format('drop policy if exists owner_all on %I', t);
    execute format('create policy owner_all on %I to agentshield_owner using (true) with check (true)', t);
  end loop;
end $$;

alter table tenants enable row level security;
alter table tenants force row level security;
drop policy if exists tenant_isolation on tenants;
create policy tenant_isolation on tenants
  using (id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
  with check (id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
drop policy if exists owner_all on tenants;
create policy owner_all on tenants to agentshield_owner using (true) with check (true);

alter table scan_rule_sets enable row level security;
alter table scan_rule_sets force row level security;
drop policy if exists tenant_read on scan_rule_sets;
create policy tenant_read on scan_rule_sets for select
  using (tenant_id is null or tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
drop policy if exists tenant_write on scan_rule_sets;
create policy tenant_write on scan_rule_sets for all
  using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
  with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
drop policy if exists owner_all on scan_rule_sets;
create policy owner_all on scan_rule_sets to agentshield_owner using (true) with check (true);

-- ── SECURITY DEFINER lookups (needed before the tenant is known) ───────────────────────────
create or replace function private.resolve_agent_key(p_prefix text)
returns table(tenant_id uuid, agent_id uuid, agent_slug text, agent_status text, key_id uuid,
              key_hash bytea, expires_at timestamptz, revoked_at timestamptz)
language sql security definer set search_path = '' stable as $$
  select k.tenant_id, k.agent_id, a.slug, a.status, k.id, k.key_hash, k.expires_at, k.revoked_at
  from public.agent_keys k join public.agents a on a.id = k.agent_id
  where k.prefix = p_prefix
$$;

create or replace function private.resolve_login(p_email citext)
returns table(tenant_id uuid, user_id uuid, password_hash text, role text, locked_until timestamptz,
              disabled_at timestamptz)
language sql security definer set search_path = '' stable as $$
  select u.tenant_id, u.id, u.password_hash, u.role, u.locked_until, u.disabled_at
  from public.users u where u.email = p_email
$$;

create or replace function private.resolve_user_token(p_prefix text)
returns table(tenant_id uuid, user_id uuid, role text, token_hash bytea, revoked_at timestamptz)
language sql security definer set search_path = '' stable as $$
  select t.tenant_id, t.user_id, u.role, t.token_hash, t.revoked_at
  from public.user_tokens t join public.users u on u.id = t.user_id
  where t.prefix = p_prefix and u.disabled_at is null
$$;

create or replace function private.create_tenant(p_name text, p_slug text, p_admin_email citext, p_password_hash text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare tid uuid;
begin
  insert into public.tenants (name, slug) values (p_name, p_slug) returning id into tid;
  insert into public.users (tenant_id, email, password_hash, role) values (tid, p_admin_email, p_password_hash, 'admin');
  return tid;
end $$;

create or replace function private.tenants_with_due_approvals(p_now timestamptz default now())
returns table(tenant_id uuid) language sql security definer set search_path = '' stable as $$
  select distinct a.tenant_id from public.approvals a where a.status = 'pending' and a.expires_at < p_now
$$;

create or replace function private.tenants_with_audit_backlog()
returns table(tenant_id uuid) language sql security definer set search_path = '' stable as $$
  select t.id from public.tenants t
$$;

-- ── ownership and grants ────────────────────────────────────────────────────────────────
do $$
declare r record;
begin
  for r in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where n.nspname = 'public' and c.relkind in ('r','p') loop
    execute format('alter table public.%I owner to agentshield_owner', r.relname);
  end loop;
  for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'private' loop
    execute format('alter function %s owner to agentshield_owner', r.sig);
  end loop;
end $$;

revoke all on all tables in schema public from public;
revoke all on all functions in schema private from public;

grant select, insert, update on tenants, users, user_tokens, agents, agent_keys, sessions, approvals,
  budget_counters, incidents, scan_rule_sets to agentshield_app;
grant select, insert, update, delete on upstreams, mcp_servers, ai_tools_seen to agentshield_app;
grant select, insert on policy_versions to agentshield_app;
grant select on audit_events, audit_payloads, audit_events_archive, audit_payloads_archive, audit_chain_heads to agentshield_app;

grant select on tenants to agentshield_worker;
grant select, insert on audit_events, audit_payloads to agentshield_worker;
grant select, insert, update on audit_chain_heads to agentshield_worker;

grant select on audit_events, audit_chain_heads, tenants to agentshield_retention;
grant select, delete on audit_payloads to agentshield_retention;
grant select, insert on audit_events_archive, audit_payloads_archive to agentshield_retention;
grant select, insert, update on budget_counters to agentshield_retention;

grant select on all tables in schema public to agentshield_readonly;

grant execute on function private.resolve_agent_key(text), private.resolve_login(citext),
  private.resolve_user_token(text), private.create_tenant(text, text, citext, text),
  private.tenants_with_due_approvals(timestamptz) to agentshield_app;
grant execute on function private.tenants_with_audit_backlog() to agentshield_worker, agentshield_app;
grant execute on function private.ensure_audit_partitions(int) to agentshield_owner;
