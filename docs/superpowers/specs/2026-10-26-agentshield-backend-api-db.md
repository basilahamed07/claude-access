# AgentShield — Backend API and Database Design (v1)

**Date:** 2026-10-26 · **Parent:** `2026-10-26-agentshield-design.md` (architecture). This document is authoritative for routes, request/response shapes, error format, and table definitions.

**Skills and references applied**
- `supabase-postgres-best-practices` (Supabase agent-skills, v1.1.1): primary keys, data types, constraints, FK indexes, RLS + RLS performance, least privilege, advisory locks, `SKIP LOCKED`, keyset pagination, partitioning, connection pooling, JSONB indexing. Rule ids are cited as `[pg:<rule>]`.
- OWASP API Security Top 10 (2023), as used by the `42crunch-api-security-testing` skill for OpenAPI audits. Cited as `[API1]…[API10]`.
- RFC 9457 (Problem Details for HTTP APIs), IETF RateLimit header fields draft, OpenAPI 3.1.

Labels as in the parent: **[Fact]**, **[My call]**, **[Guess]**.

---

# Part A — API design

## A.1 Principles [My call]

1. **Two planes, two auth schemes, one versioned prefix.**
   - *Data plane* (agents call it): `/v1/messages`, `/v1/chat/completions`, `/v1/check`, `/v1/scan`, `/v1/token`, `/v1/approvals/{id}`. Auth: agent key or agent JWT.
   - *Control plane* (people and the dashboard call it): `/v1/admin/**`, `/v1/auth/**`, `/v1/signup`. Auth: user session cookie (dashboard) or user API token (CLI).
   A data-plane credential is rejected on every control-plane route and vice versa (tested) [API5].
2. **Proxy routes mirror the provider exactly.** `/v1/messages` and `/v1/chat/completions` accept and return the provider's own wire format so an agent changes only its base URL. All AgentShield-specific information travels in `X-AgentShield-*` headers and audit events, never in the provider body (except the block/ask rewrite text).
3. **Resource-oriented JSON** for everything else: plural nouns, `snake_case` fields, ISO-8601 UTC timestamps, ids as strings.
4. **Separate input and output models** per resource (`AgentCreate`, `AgentUpdate`, `AgentRead`). Unknown fields are rejected (`extra="forbid"`), so clients cannot set `tenant_id`, `role`, `status` or other server-owned fields by mass assignment [API3].
5. **Errors are RFC 9457 `application/problem+json`** with a stable `code` (§A.5).
6. **Pagination is keyset/cursor only**: `?limit=` (default 50, max 200) and `?cursor=`; responses carry `next_cursor` or `null` [pg:data-pagination][API4].
7. **Idempotency:** every POST that creates something accepts `Idempotency-Key` (stored 24 h per tenant + route; a replay with the same key and body returns the first response; a different body → 409 `idempotency_conflict`).
8. **Optimistic concurrency:** mutable resources return `ETag`; `PATCH` and state-changing POSTs (activate a policy, decide an approval) require `If-Match` → 412 on mismatch.
9. **Tracing headers:** every response carries `X-Request-Id`; data-plane responses carry `X-AgentShield-Trace` (the `trace_id`) and, for proxy routes, `X-AgentShield-Decision-Count`.
10. **The OpenAPI 3.1 document is a build artefact that is committed** (`agentshield/openapi.json`) and checked by a snapshot test, so every API change shows up in review [API9].

## A.2 Authentication and authorization

| Caller | Credential | How it is sent | Lifetime |
|---|---|---|---|
| Agent (base-URL mode) | `ask_live_<32>` key | `Authorization: Bearer …` **or** `x-api-key: …` (Anthropic SDKs use the latter) | until revoked/rotated |
| Agent (check/SDK) | agent JWT (HS256 or EdDSA, `sub=agent slug`, `tid`, `exp` 15 min) from `POST /v1/token` | `Authorization: Bearer …` | 15 min |
| Passthrough provider key | provider key | `X-Upstream-Authorization: Bearer …` | never stored |
| Dashboard user | session cookie `as_session` (`HttpOnly; Secure; SameSite=Lax`, 12 h idle) + CSRF token header `X-CSRF-Token` on unsafe methods | cookie | 12 h |
| CLI user | user API token `asu_<32>` (hashed like agent keys) | `Authorization: Bearer …` | until revoked |

**Roles** (`admin`, `analyst`, `viewer`) are enforced by one dependency per route (`require_role("analyst")`), and a test enumerates the route table to assert every control-plane route declares a role [API5].

| Capability | viewer | analyst | admin |
|---|---|---|---|
| Read agents, policies, events (payloads redacted), sessions | ✓ | ✓ | ✓ |
| Decide approvals, mark incidents, run simulations, export | | ✓ | ✓ |
| Create/rotate keys, edit/activate policies, manage upstreams, users | | | ✓ |

An agent credential can never decide an approval, even for its own request [API6].

**Login hardening:** argon2id (`m=64 MiB, t=3, p=1`), 5 failed logins per account per 15 min → 15 min lock, generic error message, timing-equal paths for unknown users [API2].

## A.3 Endpoint catalog

Legend: **Idem** = accepts `Idempotency-Key`; **Role** = minimum role (control plane).

### Data plane
| Method | Path | Purpose | Notes |
|---|---|---|---|
| POST | `/v1/messages` | Anthropic Messages proxy (stream + non-stream) | provider body in/out; scans `tool_result`; rewrites blocked `tool_use` |
| POST | `/v1/chat/completions` | OpenAI-compatible proxy (stream + non-stream) | same, for `tool_calls` / `role: tool` |
| GET | `/v1/models` | lists the agent's upstream model aliases | some SDKs call it at start-up |
| POST | `/v1/check` | decide one planned tool call | body §A.4.1; `wait_seconds` ≤ 30 for `ask` long-poll |
| POST | `/v1/scan` | scan one piece of untrusted content | body §A.4.2 |
| POST | `/v1/token` | exchange agent key → 15-min JWT | |
| GET | `/v1/approvals/{approval_id}` | poll an approval created for this agent | 404 for other agents' approvals |

### Control plane
| Method | Path | Role | Idem | Purpose |
|---|---|---|---|---|
| POST | `/v1/signup` | public, rate-limited | ✓ | create tenant + first admin (can be disabled: `AGENTSHIELD_SIGNUP=closed`) |
| POST | `/v1/auth/login` · `/v1/auth/logout` | public / any | | session cookie |
| GET | `/v1/auth/me` | any | | current user, role, tenant |
| GET/POST | `/v1/admin/users` · PATCH/DELETE `/v1/admin/users/{id}` | admin | ✓ | manage users |
| GET/POST | `/v1/admin/upstreams` · GET/PATCH/DELETE `…/{id}` | admin | ✓ | provider connections; key write-only |
| POST | `/v1/admin/upstreams/{id}/test` | admin | | send a 1-token request to verify the connection |
| GET/POST | `/v1/admin/agents` · GET/PATCH `…/{slug}` | viewer / admin | ✓ | registry |
| POST | `/v1/admin/agents/{slug}/keys` | admin | ✓ | issue key; **plaintext returned once** |
| GET | `/v1/admin/agents/{slug}/keys` | admin | | prefixes, created/expiry/revoked only |
| POST | `/v1/admin/agents/{slug}/keys/{key_id}/revoke` | admin | | |
| POST | `/v1/admin/agents/{slug}/keys/{key_id}/rotate` | admin | ✓ | `{overlap_seconds ≤ 604800}` → new key (plaintext once); old key gets `expires_at = now + overlap` |
| GET | `/v1/admin/agents/{slug}/snippet?lang=python-openai|python-anthropic|curl|claude-code` | admin | | copy-paste connection snippet |
| GET/POST | `/v1/admin/agents/{slug}/policy/versions` | viewer / admin | ✓ | list / create (validates; returns line-numbered errors) |
| GET | `/v1/admin/agents/{slug}/policy/versions/{v}` | viewer | | |
| POST | `/v1/admin/agents/{slug}/policy/versions/{v}/activate` | admin | | `If-Match` required |
| POST | `/v1/admin/agents/{slug}/policy/simulate` | analyst | | `{version, session_ids[] | since}` → per-call diff |
| GET | `/v1/admin/approvals?status=pending` | analyst | | queue |
| POST | `/v1/admin/approvals/{id}/decision` | analyst | | `{approve: bool, note}`; `If-Match`; 409 if already decided |
| GET | `/v1/admin/events` | viewer | | filters: `agent, session, trace, user, tool, decision, module, type, severity, from, to` |
| GET | `/v1/admin/sessions` · `…/{id}` · `…/{id}/timeline` | viewer | | |
| POST | `/v1/admin/sessions/{id}/replay` | analyst | | `{policy_version?}` → steps + diffs |
| GET | `/v1/admin/sessions/{id}/export.json` | analyst | | events + chain head + verification result |
| GET/POST | `/v1/admin/incidents` · PATCH `…/{id}` | viewer / analyst | ✓ | |
| GET | `/v1/admin/alerts` | viewer | | derived: blocked calls, malicious scans, approvals expired, budget exceeded, chain failures |
| GET | `/v1/admin/stats/overview?window=24h|7d` | viewer | | counts for the overview screen |
| GET · PATCH | `/v1/admin/settings` | viewer / admin | | tenant settings: `on_malicious`, `webhook_url`, retention overrides (validated against floors), `judge_upstream_id` |
| POST | `/v1/admin/scan-rules/reload` | admin | | hot-reload signatures |
| GET | `/v1/admin/audit/verify` | analyst | | run chain verification for the tenant (rate-limited) |
| GET | `/healthz` · `/readyz` · `/metrics` | none / none / internal network only | | |

## A.4 Key schemas

### A.4.1 Check
Request — exactly the prompt §9 shape [Fact], plus optional fields:
```json
{
  "agent_id": "email-reader-01",
  "tenant": "acme",
  "session_id": "s-9f2c",
  "action": { "tool": "send_email", "arguments": { "to": "x@unknown.com", "body": "..." }, "effect_tag": "external" },
  "context": {
    "user_request": "Summarize my unread mail",
    "end_user": "u-8f3a",
    "untrusted_inputs": [{ "source": "email", "id": "m-441", "text": "..." }]
  },
  "wait_seconds": 0
}
```
- `agent_id` and `tenant` are **checked against the credential** and a mismatch is 403 `credential_mismatch`; they are never used to choose the tenant [API1].
- `effect_tag` from the caller is advisory; the policy's tag wins.
- `untrusted_inputs` are scanned (M2) before the decision; total ≤ 1 MB.

Response — the prompt §9 shape plus `approval_id`, `mode`, `would_have`:
```json
{ "decision": "block", "reason": "…", "rule_id": "deny-external-send", "risk_score": 0.92,
  "findings": [{ "module": "injection", "span": "m-441:120-210", "rule_id": "inj-forward-all" }],
  "approval_id": null, "mode": "enforce", "would_have": null, "trace_id": "t-77ab" }
```

### A.4.2 Scan
As in the parent §2.2; `text` ≤ 1 MB per item (larger → 413 `payload_too_large`; the gateway's proxy path truncates instead, see parent §2.2 failure modes).

### A.4.3 Agent
```json
// AgentCreate
{ "slug": "email-reader-01", "name": "Email reader", "owner": "ops@acme.com", "purpose": "Summarize inbox",
  "risk_tier": "medium", "mode": "monitor", "key_mode": "stored", "upstream_id": "0192…" }
// AgentRead adds: id, created_at, updated_at, active_policy_version, status, key_count, last_seen_at, etag
```
`slug` matches `^[a-z0-9][a-z0-9-]{1,62}$` and is immutable after creation.

### A.4.4 Upstream
```json
// UpstreamCreate (key is write-only, never returned)
{ "name": "acme-openai", "kind": "openai", "base_url": "https://api.openai.com/v1",
  "api_key": "sk-…",
  "model_map": { "gpt-default": { "model": "gpt-4.1-mini", "input_micro_usd_per_mtok": 400000, "output_micro_usd_per_mtok": 1600000 } },
  "judge_model": "gpt-4.1-mini" }
// UpstreamRead: id, name, kind, base_url, has_key: true, model_map, judge_model, created_at
```
Prices are per million tokens in micro-USD and are entered by the tenant (AgentShield ships no price list); a model without prices counts calls and tokens but costs 0 and emits a `budget.price_missing` warning once per day.

### A.4.5 Approval, event, timeline
```json
// Approval
{ "id": "0192…", "agent_id": "pay-bot", "session_id": "s-1", "trace_id": "t-…", "tool": "pay_invoice",
  "arguments_redacted": { "amount": 5000, "payee": "ACME Ltd" }, "rule_id": "ask-large-payment",
  "status": "pending", "requested_at": "…", "expires_at": "…", "decided_by": null, "decided_at": null, "note": null }
// Timeline step (GET …/timeline)
{ "seq": 1042, "ts": "…", "trace_id": "t-…", "module": "policy", "type": "policy.decision",
  "decision": "block", "rule_id": "deny-external-send", "severity": "high",
  "summary": "send_email to x@unknown.com blocked", "payload": { … } , "payload_available": true }
```

## A.5 Error model (RFC 9457)
```json
{ "type": "https://agentshield.dev/errors/policy_invalid", "title": "Policy is invalid",
  "status": 422, "code": "policy_invalid", "detail": "Unknown operator 'contains' at line 14",
  "instance": "/v1/admin/agents/email-reader-01/policy/versions", "request_id": "req_…",
  "errors": [{ "line": 14, "path": "rules[2].when.op", "message": "unknown operator" }] }
```
Stable codes: `unauthenticated` 401, `forbidden` 403, `credential_mismatch` 403, `not_found` 404 (also used for other tenants' ids), `conflict` 409, `idempotency_conflict` 409, `precondition_failed` 412, `payload_too_large` 413, `validation_failed` 422, `policy_invalid` 422, `rate_limited` 429 (+ `Retry-After`), `budget_exceeded` 429, `upstream_error` 502, `upstream_timeout` 504, `internal` 500 (no stack traces, no secrets).

**Proxy routes never return AgentShield errors for policy decisions** — blocks are rewrites (parent §3.1). They return AgentShield errors only for auth (401), rate/budget limits (429, in the provider's own error shape so SDKs retry/handle correctly), and size (413).

## A.6 OWASP API Security Top 10 (2023) mapping

| Risk | Where it could happen here | Control | Test |
|---|---|---|---|
| API1 Broken object-level authorization | any `{slug}`, `{id}` from another tenant | `TenantContext` in every repository call **and** Postgres RLS; 404 for foreign ids | parametrized route-table test (all ids from tenant B with tenant A creds → 404) |
| API2 Broken authentication | agent keys, login | HMAC-hashed keys, constant-time compare, argon2id, lockout, short JWT, cookie flags | key/JWT/lockout unit tests |
| API3 Broken object-property-level authorization | mass assignment, over-exposure | separate Create/Update/Read models, `extra="forbid"`, write-only `api_key` | schema tests: Read models contain no `key_hash`, `key_ciphertext`, `password_hash` |
| API4 Unrestricted resource consumption | proxy, scan, search | per-key rate limits, per-agent budgets, 2 MB request cap, 1 MB scan item cap, `limit ≤ 200`, query timeouts (`statement_timeout=5s` for app role) | 429/413 tests |
| API5 Broken function-level authorization | admin routes | `require_role` on every route; data-plane creds rejected on control plane | route-table role test |
| API6 Unrestricted access to sensitive business flows | approvals, signup | approver must be a user with analyst+; an agent cannot decide; signup rate-limited + can be closed | approval auth tests |
| API7 Server-side request forgery | tenant-supplied `upstreams.base_url`, `webhook_url`, `/upstreams/{id}/test` | URL validator: `https` only (http allowed only for hosts in `AGENTSHIELD_ALLOW_PRIVATE_UPSTREAMS`, e.g. local vLLM/Ollama in self-host); resolve DNS and reject private, loopback, link-local, metadata (169.254.169.254) ranges; re-check on every connect (DNS rebinding); no redirects followed | SSRF unit tests incl. `http://169.254.169.254`, `http://[::1]`, DNS that resolves to `10.x` |
| API8 Security misconfiguration | headers, CORS, debug | no wildcard CORS (dashboard origin only), security headers, `debug=False`, OpenAPI docs UI disabled in prod | config test |
| API9 Improper inventory management | undocumented routes | committed OpenAPI snapshot; route-table tests | snapshot test |
| API10 Unsafe consumption of APIs | upstream model responses, webhooks | response size cap (10 MB), strict SSE parsing, tool-call JSON parsed defensively, upstream timeouts (connect 5 s, read 120 s), never trust upstream `usage` for limits without a sanity cap | rewrite/upstream tests |

## A.7 Limits and timeouts [My call]
Request body 2 MB (proxy), 1 MB per scan item, 64 KB event payload (stored), 10 MB upstream response, `limit` ≤ 200, `wait_seconds` ≤ 30, default rate limits per agent key: 600 req/min proxy, 1,200 req/min check/scan (overridable per agent by policy `budgets.max_rpm`).

## A.8 API testing
- Contract snapshot of `openapi.json`.
- **Property-based API fuzzing with Schemathesis** against the running app in CI (all control-plane routes, checks: no 5xx, responses match schema).
- Route-table tests for roles (API5) and tenant isolation (API1).
- Optional: the 42Crunch audit skill can be run on `openapi.json` by anyone with a 42Crunch account; not required in CI.

---

# Part B — Database design (PostgreSQL 18)

## B.1 Conventions [pg rules cited]
- **Primary keys:** `uuid primary key default uuidv7()` (built into PostgreSQL 18) — time-ordered so inserts stay local in the index, and safe to expose in URLs [pg:schema-primary-keys]. `audit_events` uses a per-tenant `seq bigint` assigned by the worker.
- **Types:** `text` (+ `check` for enumerations and length), `timestamptz`, `boolean`, `bigint` for counters and micro-USD money, `jsonb` only for genuinely schemaless data (policy parse tree, event payload, model maps) [pg:schema-data-types].
- **Names:** lowercase snake_case, no quoted identifiers [pg:schema-lowercase-identifiers]; constraint names `<table>_<cols>_<kind>`.
- **Every foreign key column is indexed** (most as the second column of a `(tenant_id, …)` index) [pg:schema-foreign-key-indexes].
- **Every tenant table:** `tenant_id uuid not null references tenants(id)`, RLS enabled and forced, and indexes lead with `tenant_id` [pg:security-rls-basics][pg:security-rls-performance].
- `created_at timestamptz not null default now()`, `updated_at` maintained by a trigger where rows are mutable.
- Migrations: Alembic, one revision per change, idempotent DDL (`if not exists`, `do $$ … $$` guards for constraints since `ADD CONSTRAINT IF NOT EXISTS` doesn't exist) [pg:schema-constraints]; destructive migrations need a two-step expand/contract.

## B.2 Roles, RLS and per-request tenant context
```sql
create role agentshield_owner    nologin;        -- owns schema; migrations run as this
create role agentshield_app      nologin;        -- gateway / API
create role agentshield_worker   nologin;        -- audit worker
create role agentshield_retention nologin;       -- retention job
create role agentshield_readonly nologin;        -- reporting
-- login roles inherit one of the above; none is superuser; none has BYPASSRLS  [pg:security-privileges]
revoke all on schema public from public;
create schema private;                            -- SECURITY DEFINER helpers, not exposed
```
**RLS pattern** (applied to every tenant table by a migration helper):
```sql
alter table agents enable row level security;
alter table agents force row level security;
create policy tenant_isolation on agents
  using      (tenant_id = (select current_setting('app.tenant_id', true))::uuid)
  with check (tenant_id = (select current_setting('app.tenant_id', true))::uuid);
```
- The `(select …)` wrapper makes Postgres evaluate the setting once per query, not per row [pg:security-rls-performance].
- The app opens a transaction per request and runs `select set_config('app.tenant_id', $1, true)` (transaction-local, so it is safe with PgBouncer transaction pooling) [pg:conn-pooling]. If the setting is missing, `current_setting(..., true)` returns NULL and **no rows match** — fail closed.
- **Lookups that must happen before the tenant is known** run through `SECURITY DEFINER` functions in `private`, with `set search_path = ''`, `EXECUTE` granted only to `agentshield_app`, returning the minimum columns:
  - `private.resolve_agent_key(p_prefix text) returns table(tenant_id uuid, agent_id uuid, key_id uuid, key_hash bytea, expires_at timestamptz, revoked_at timestamptz)`
  - `private.resolve_login(p_email citext) returns table(tenant_id uuid, user_id uuid, password_hash text, role text, locked_until timestamptz)`
  - `private.create_tenant(p_name text, p_admin_email citext, p_password_hash text) returns uuid`

## B.3 DDL
```sql
create extension if not exists citext;

create table tenants (
  id          uuid primary key default uuidv7(),
  name        text not null check (length(name) between 2 and 100),
  slug        text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  settings    jsonb not null default '{}'::jsonb,   -- on_malicious, retention overrides, webhook_url
  created_at  timestamptz not null default now()
);

create table users (
  id            uuid primary key default uuidv7(),
  tenant_id     uuid not null references tenants(id),
  email         citext not null unique,              -- global: login needs no tenant picker
  password_hash text not null,
  role          text not null check (role in ('admin','analyst','viewer')),
  failed_logins int  not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  disabled_at   timestamptz
);
create index users_tenant_idx on users (tenant_id);

create table user_tokens (                           -- CLI tokens
  id uuid primary key default uuidv7(), tenant_id uuid not null references tenants(id),
  user_id uuid not null references users(id), prefix text not null unique, token_hash bytea not null,
  created_at timestamptz not null default now(), revoked_at timestamptz
);
create index user_tokens_tenant_user_idx on user_tokens (tenant_id, user_id);

create table upstreams (
  id             uuid primary key default uuidv7(),
  tenant_id      uuid not null references tenants(id),
  name           text not null,
  kind           text not null check (kind in ('anthropic','openai','openai_compat')),
  base_url       text not null,
  key_ciphertext bytea,                               -- Fernet; null for passthrough-only upstreams
  model_map      jsonb not null default '{}'::jsonb,
  judge_model    text,
  created_at     timestamptz not null default now(),
  unique (tenant_id, name)
);

create table agents (
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
  last_seen_at          timestamptz,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  unique (tenant_id, slug)
);
create index agents_tenant_upstream_idx on agents (tenant_id, upstream_id);

create table agent_keys (
  id          uuid primary key default uuidv7(),
  tenant_id   uuid not null references tenants(id),
  agent_id    uuid not null references agents(id),
  prefix      text not null unique,                   -- first 12 chars, used by resolve_agent_key
  key_hash    bytea not null,                         -- HMAC-SHA256(pepper, key)
  created_at  timestamptz not null default now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);
create index agent_keys_tenant_agent_idx on agent_keys (tenant_id, agent_id);

create table policy_versions (
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
create index policy_versions_created_by_idx on policy_versions (created_by);
-- immutable: trigger rejects UPDATE/DELETE

create table sessions (
  id           uuid primary key default uuidv7(),
  tenant_id    uuid not null references tenants(id),
  agent_id     uuid not null references agents(id),
  session_key  text not null check (length(session_key) <= 200),   -- client header value or derived hash
  user_request text,
  risk_score   real not null default 0 check (risk_score between 0 and 1),
  started_at   timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (tenant_id, agent_id, session_key)
);
create index sessions_tenant_last_seen_idx on sessions (tenant_id, last_seen_at desc);

create table approvals (
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
create index approvals_tenant_agent_idx   on approvals (tenant_id, agent_id);
create index approvals_session_idx        on approvals (session_id);
create index approvals_decided_by_idx     on approvals (decided_by);
create index approvals_pending_expiry_idx on approvals (expires_at) where status = 'pending';   -- [pg:query-partial-indexes]

create table budget_counters (                        -- hourly mirror of Redis counters, for reporting
  tenant_id      uuid not null references tenants(id),
  agent_id       uuid not null references agents(id),
  day            date not null,
  tokens         bigint not null default 0,
  cost_micro_usd bigint not null default 0,
  calls          bigint not null default 0,
  primary key (tenant_id, agent_id, day)
);
create index budget_counters_agent_idx on budget_counters (agent_id);

create table incidents (
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
create index incidents_tenant_status_idx on incidents (tenant_id, status, created_at desc);
create index incidents_session_idx on incidents (session_id);
create index incidents_created_by_idx on incidents (created_by);

create table scan_rule_sets (                         -- versioned signature sets for hot reload
  id uuid primary key default uuidv7(), tenant_id uuid references tenants(id),   -- null = platform default
  version int not null, yaml text not null, sha256 bytea not null, active boolean not null default false,
  created_at timestamptz not null default now(), unique (tenant_id, version)
);

-- ── audit (append-only, partitioned) ─────────────────────────────────────────
create table audit_events (
  tenant_id         uuid not null,
  seq               bigint not null,
  ts                timestamptz not null,
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
  otel_span_id      text,
  prev_hash         bytea not null,
  hash              bytea not null,
  primary key (tenant_id, seq, ts)
) partition by range (ts);                            -- [pg:schema-partitioning]
-- monthly partitions created ahead by a job: audit_events_2026_11 … ; a default partition catches stragglers
create index audit_events_trace_idx    on audit_events (tenant_id, trace_id);
create index audit_events_session_idx  on audit_events (tenant_id, session_id, seq);
create index audit_events_filter_idx   on audit_events (tenant_id, ts desc, seq desc);
create index audit_events_decision_idx on audit_events (tenant_id, decision, ts desc) where decision is not null;
create index audit_events_user_idx     on audit_events (tenant_id, end_user, ts desc) where end_user is not null;

create table audit_payloads (                         -- bodies, purged on a shorter schedule
  tenant_id  uuid not null,
  seq        bigint not null,
  ts         timestamptz not null,
  session_id uuid,                                    -- lets retention keep incident payloads
  payload    jsonb not null,                          -- already redacted, ≤ 64 KB
  primary key (tenant_id, seq, ts)
) partition by range (ts);

create table audit_events_archive (like audit_events including all);  -- incident sessions copied here before partitions are dropped; not partitioned
create table audit_payloads_archive (like audit_payloads including all);

create table audit_chain_heads (                      -- one row per tenant; serialized by advisory lock
  tenant_id uuid primary key references tenants(id),
  last_seq  bigint not null,
  last_hash bytea not null
);

-- later stages (created now so contracts are stable; empty in v1)
create table mcp_servers (
  id uuid primary key default uuidv7(), tenant_id uuid not null references tenants(id),
  name text not null, ref text not null, pinned_version text not null, fingerprint bytea,
  verdict text not null default 'pending' check (verdict in ('pending','approved','approved_with_limits','rejected','suspended')),
  owner text not null, report jsonb, created_at timestamptz not null default now(), unique (tenant_id, name)
);
create table ai_tools_seen (
  id uuid primary key default uuidv7(), tenant_id uuid not null references tenants(id),
  domain text not null, vendor text, classification text not null check (classification in ('approved','tolerated','blocked','unknown')),
  team text, first_seen timestamptz not null, last_seen timestamptz not null, unique (tenant_id, domain, team)
);
```
**Append-only enforcement** on `audit_events`, `audit_chain_heads` writes and `policy_versions`:
```sql
create function private.reject_mutation() returns trigger language plpgsql as $$
begin raise exception 'append-only table %', tg_table_name using errcode = '42501'; end $$;
create trigger audit_events_no_update before update or delete on audit_events
  for each row execute function private.reject_mutation();
-- grants: app = select; worker = insert on audit_events/audit_payloads, select+update on audit_chain_heads;
-- retention = may DETACH/DROP partitions and DELETE from audit_payloads (a separate trigger-free path, logged as audit.checkpoint)
```

## B.4 Query patterns and indexes
| Query | Index used |
|---|---|
| Resolve key by prefix (every request; also cached in-process 60 s) | `agent_keys.prefix` unique |
| Session timeline `where tenant_id=? and session_id=? order by seq` | `audit_events_session_idx` |
| Events by end user | partial `audit_events_user_idx` |
| Trace lookup | `audit_events_trace_idx` |
| Events list with filters, newest first, keyset `(ts, seq) < (?, ?)` | `audit_events_filter_idx` (+ partition pruning on `ts`) |
| Alerts: blocked decisions in window | partial `audit_events_decision_idx` |
| Pending approvals due to expire | partial `approvals_pending_expiry_idx` |
| Agent list | `unique (tenant_id, slug)` |
No GIN index on payloads in v1 (search is by envelope columns); add `jsonb_path_ops` GIN only if payload containment search becomes a feature [pg:advanced-jsonb-indexing].

## B.5 Concurrency
- **Hash chain:** the worker groups stream messages by tenant; per tenant it opens a transaction, takes `pg_advisory_xact_lock(hashtextextended(tenant_id::text, 0))`, reads `audit_chain_heads`, inserts the batch with consecutive `seq`, updates the head, commits [pg:lock-advisory][pg:lock-short-transactions]. Two workers can run; they never interleave a tenant's chain.
- **Approval expiry job:** every 10 s: `update approvals set status='expired', decided_at=now() where id in (select id from approvals where status='pending' and expires_at < now() order by expires_at limit 100 for update skip locked) returning …` [pg:lock-skip-locked]. It must run as a role with RLS context per tenant → the job iterates tenants with due approvals via `private.tenants_with_due_approvals()`.
- **Policy activation:** `update agents set active_policy_version = $v, updated_at = now() where id = $a and updated_at = $etag_ts` → 0 rows ⇒ 412.
- Short transactions everywhere; no transaction is held across an upstream HTTP call.

## B.6 Partitioning and retention jobs
- `audit_events` and `audit_payloads`: monthly range partitions, created 3 months ahead by `agentshield db ensure-partitions` (run daily).
- Payload purge (daily): `delete from audit_payloads where ts < now() - tenant.payload_retention and (session_id is null or session_id not in (select session_id from incidents))` in batches of 10k.
- Envelope retention (monthly): when a partition is entirely older than the envelope retention for **all** tenants, emit `audit.checkpoint` (last `seq` + `hash` per tenant in the range) then `detach` + `drop`. Incident sessions are copied to `audit_events_archive` / `audit_payloads_archive` before dropping (B17; tables created in B2's migration).

## B.7 Redis (ephemeral state only — losing Redis loses no audit data once spooled)
| Key | Type | TTL | Use |
|---|---|---|---|
| `stream:audit.events` | stream, consumer group `audit-writers` | trimmed `MAXLEN ~ 1e6` | event bus |
| `risk:{tenant}:{session}` | string (float) | 24 h | session risk (mirrored to `sessions.risk_score`) |
| `budget:{tenant}:{agent}:{yyyymmdd}` | hash `tokens,cost,calls` | 48 h | budgets |
| `rpm:{tenant}:{agent}:{epoch_min}` | counter | 120 s | rate limit |
| `allow:{tenant}:{session}:{tool}:{args_hash}` | string | 900 s | approved-call allowance |
| `approval:{id}` | pub/sub channel | — | long-poll wakeup |
| `idem:{tenant}:{route}:{key}` | string (response JSON) | 24 h | idempotency |
| `keycache:{prefix}` | — | — | **not** used: key cache is in-process only, so a Redis compromise cannot forge keys |

## B.8 Connection management
SQLAlchemy async engine, `pool_size = 2 × CPU cores`, `max_overflow = 5`, `pool_pre_ping`, `statement_timeout = 5s` and `idle_in_transaction_session_timeout = 10s` set on the app role [pg:conn-pooling][pg:conn-idle-timeout]. PgBouncer in transaction mode is optional for larger installs; it is compatible because tenant context is transaction-local.

## B.9 Database tests (owned by plan task B2)
RLS: with `app.tenant_id` = A, every tenant table returns zero rows of tenant B, inserts with tenant B are rejected, and with the setting unset no rows are visible; app role cannot UPDATE/DELETE `audit_events`; the "missing FK index" query from [pg:schema-foreign-key-indexes] returns no rows; `uuidv7()` ids sort by creation time; partition creation is idempotent.
