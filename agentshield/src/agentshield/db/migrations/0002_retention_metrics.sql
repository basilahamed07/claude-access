-- Retention (partition drop with a hard age floor) and cross-tenant counters for metrics.

-- Partitions must always belong to the owner role (the drop function runs as it), whoever calls this.
create or replace function private.ensure_audit_partitions(months_ahead int default 3) returns int
language plpgsql security definer set search_path = public, pg_catalog as $$
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

create or replace function private.drop_audit_partition(p_year int, p_month int, p_now timestamptz default now())
returns boolean language plpgsql security definer set search_path = '' as $$
declare
  suffix text := p_year::text || '_' || lpad(p_month::text, 2, '0');
  first_day timestamptz := make_date(p_year, p_month, 1)::timestamptz;
  dropped boolean := false;
begin
  -- Hard floor: envelopes are kept at least 180 days whatever the caller asks for.
  if first_day + interval '1 month' > p_now - interval '180 days' then
    raise exception 'audit partition % is younger than 180 days', suffix using errcode = '42501';
  end if;
  if to_regclass('public.audit_events_' || suffix) is not null then
    execute format('alter table public.audit_events detach partition public.%I', 'audit_events_' || suffix);
    execute format('drop table public.%I', 'audit_events_' || suffix);
    dropped := true;
  end if;
  if to_regclass('public.audit_payloads_' || suffix) is not null then
    execute format('alter table public.audit_payloads detach partition public.%I', 'audit_payloads_' || suffix);
    execute format('drop table public.%I', 'audit_payloads_' || suffix);
    dropped := true;
  end if;
  return dropped;
end $$;

create or replace function private.audit_partitions()
returns table(year int, month int) language sql security definer set search_path = '' stable as $$
  select substring(c.relname from '_(\d{4})_\d{2}$')::int, substring(c.relname from '_(\d{2})$')::int
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r' and c.relname ~ '^audit_events_\d{4}_\d{2}$'
$$;

create or replace function private.count_pending_approvals() returns bigint
language sql security definer set search_path = '' stable as $$
  select count(*) from public.approvals where status = 'pending'
$$;

do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'private' loop
    execute format('alter function %s owner to agentshield_owner', r.sig);
  end loop;
end $$;

revoke all on function private.drop_audit_partition(int, int, timestamptz), private.audit_partitions(),
  private.count_pending_approvals() from public;
grant execute on function private.drop_audit_partition(int, int, timestamptz), private.audit_partitions()
  to agentshield_retention;
grant execute on function private.count_pending_approvals() to agentshield_app;
grant select on incidents, sessions to agentshield_retention;
grant execute on function private.tenants_with_audit_backlog() to agentshield_retention;
