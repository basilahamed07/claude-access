-- Shadow AI inventory: what was seen, how much, and how to describe it. Raw user names are never stored (hashed counts only).
alter table ai_tools_seen add column if not exists category text;
alter table ai_tools_seen add column if not exists risk text;
alter table ai_tools_seen add column if not exists suggested_alternative text;
alter table ai_tools_seen add column if not exists source text;
alter table ai_tools_seen add column if not exists reason text;                       -- why it was recognised: catalog entry or heuristic
alter table ai_tools_seen add column if not exists hits bigint not null default 0;
alter table ai_tools_seen add column if not exists bytes_out bigint not null default 0;
alter table ai_tools_seen add column if not exists users_count integer not null default 0;
alter table ai_tools_seen add column if not exists classified_by uuid references users(id);
create index if not exists ai_tools_seen_tenant_last_idx on ai_tools_seen (tenant_id, last_seen desc);
create index if not exists ai_tools_seen_classified_by_idx on ai_tools_seen (classified_by);
alter table user_tokens add column if not exists label text not null default '';
grant update on ai_tools_seen to agentshield_app;
