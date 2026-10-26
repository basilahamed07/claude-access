-- An ingest token can only send logs; it cannot be used for anything else the person who made it could do.
alter table user_tokens add column if not exists scope text not null default 'full' check (scope in ('full', 'ingest'));

drop function if exists private.resolve_user_token(text);
create function private.resolve_user_token(p_prefix text)
returns table(tenant_id uuid, user_id uuid, role text, token_hash bytea, revoked_at timestamptz, scope text)
language sql security definer set search_path = '' stable as $$
  select t.tenant_id, t.user_id, u.role, t.token_hash, t.revoked_at, t.scope
  from public.user_tokens t join public.users u on u.id = t.user_id
  where t.prefix = p_prefix and u.disabled_at is null
$$;
grant execute on function private.resolve_user_token(text) to agentshield_app;
