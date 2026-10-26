-- MCP server registry: where to reach a server, what it exposed when it was approved, and which tools are allowed.
alter table mcp_servers add column if not exists url text;
alter table mcp_servers add column if not exists tools jsonb;                 -- tool snapshot (name, description, inputSchema) taken at the last scan
alter table mcp_servers add column if not exists allowed_tools text[];        -- null = all scanned tools; set for 'approved_with_limits'
alter table mcp_servers add column if not exists declared_capabilities text[] not null default '{}';
alter table mcp_servers add column if not exists purpose text not null default '';
alter table mcp_servers add column if not exists approved_fingerprint bytea;  -- the fingerprint a human approved; drift is measured against this
alter table mcp_servers add column if not exists scanned_at timestamptz;
alter table mcp_servers add column if not exists updated_at timestamptz not null default now();
alter table mcp_servers drop constraint if exists mcp_servers_ref_len;
alter table mcp_servers add constraint mcp_servers_ref_len check (length(ref) <= 500);
create index if not exists mcp_servers_tenant_verdict_idx on mcp_servers (tenant_id, verdict);
drop trigger if exists mcp_servers_touch on mcp_servers;
create trigger mcp_servers_touch before update on mcp_servers for each row execute function private.touch_updated_at();
alter table mcp_servers add column if not exists auth_ciphertext bytea;       -- optional bearer token for the server (encrypted, write-only)
