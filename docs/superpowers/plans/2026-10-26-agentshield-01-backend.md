# AgentShield Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the AgentShield Python service: multi-tenant universal proxy (Anthropic + OpenAI formats), check/scan APIs, permission policies with approvals and budgets, a layered injection firewall, and a hash-chained audit log with replay — stages 1–4 backend.

**Architecture:** One FastAPI app (data plane + control plane) runs M1 and M2 in-process behind interfaces; a separate audit worker is the only writer of the partitioned, append-only `audit_events`. Postgres 18 holds state with RLS for tenant isolation; Redis 7 holds ephemeral counters and the event stream.

**Tech Stack:** Python 3.12, FastAPI, uvicorn, httpx, pydantic v2, SQLAlchemy 2 async + asyncpg, Alembic, PostgreSQL 18, Redis 7 (redis-py asyncio), PyYAML, cryptography (Fernet), argon2-cffi, PyJWT, onnxruntime + tokenizers, python-ulid; tests: pytest, pytest-asyncio, respx, fakeredis, testcontainers, hypothesis, schemathesis.

**Spec:** `docs/superpowers/specs/2026-10-26-agentshield-design.md` (architecture, "arch §n") and `docs/superpowers/specs/2026-10-26-agentshield-backend-api-db.md` (routes and DDL, "api §A.n" / "db §B.n"). Executors read both.

## Global Constraints

- Default deny: no matching rule → `block`, `rule_id="default-deny"`; precedence `block > ask > allow` (arch §2.1).
- Effect tags exactly `read, write, destructive, external, financial, execute`; untagged → `external`; fail rule: only `read` may fail open (arch §7.4, §8.6).
- Tenant comes from the credential only; every repository function takes `TenantContext`; every request transaction runs `set_config('app.tenant_id', …, true)`; RLS forced on all tenant tables (db §B.2).
- Agent id on the wire = slug `^[a-z0-9][a-z0-9-]{1,62}$`; DB keys `uuid default uuidv7()` (db §B.1).
- Agent key `ask_live_` + 32 url-safe chars, stored as HMAC-SHA256 with server pepper, `prefix` = first 16 chars (`ask_live_` + 7 random); shown once (arch §4.1).
- Provider keys Fernet-encrypted with `AGENTSHIELD_MASTER_KEY`; never returned, logged, or put in events (arch §8.2).
- Errors `application/problem+json` with the stable codes in api §A.5; proxy routes rewrite blocks instead of erroring.
- Blocked tool block text: `Action blocked by AgentShield: <reason> (rule <id>, trace <trace_id>)`; ask text: `Action needs human approval (approval <id>, rule <rule_id>); it was not executed.`; all tool blocks replaced → `stop_reason=end_turn` / `finish_reason=stop` (arch §3.1).
- Approvals expire after 300 s; approved `(session, tool, args_hash)` allowed for 900 s, same session only (arch §2.1, §7.2a).
- Judge band 0.35–0.80, timeout 1.5 s → `suspicious` 0.5; risk update `r' = 1-(1-r)*(1-0.6*c)` (arch §2.2).
- Redact before publish; payload ≤ 64 KB stored in `audit_payloads`; chain hash `sha256(prev_hash || canonical_json(envelope_without_prev_hash_and_hash))` where the envelope includes `payload_sha256` (arch §4.2).
- Retention: payloads 30 d, envelopes 180 d (floor), incidents/approvals 3 y (arch §2.5).
- Limits: 2 MB proxy body, 1 MB scan item, `limit` ≤ 200, `wait_seconds` ≤ 30 (api §A.7).
- Latency targets [unmeasured]: policy eval p95 < 20 ms; normalizer+rules p95 < 30 ms; rule-only decision path < 200 ms.

## Review Focus

1. **A tool call split across stream chunks** (1-byte chunking, `input_json_delta` split mid-token) must never leak a blocked call → B5.
2. **A mixed turn** (text + allowed tool + blocked tool) keeps the text and the allowed call → B5.
3. **Missing `app.tenant_id`** (a code path that forgot the context) must return zero rows, not all rows → B2.
4. **Tenant-supplied URLs** (`base_url`, `webhook_url`) pointing at `169.254.169.254`, loopback, private ranges, or DNS that rebinds to them are rejected → B3.
5. **OpenAI `arguments` as a JSON string, malformed JSON, or missing arguments** evaluate without an exception (unknown → default-deny) → B8, B10.
6. **Benign text that quotes attack phrases** stays below the suspicious threshold → B13.
7. **Redis down mid-request:** effectful tools blocked, `read` tools allowed, events spooled and an `audit.gap` emitted → B6, B10.
8. **Two workers writing the same tenant's first events** don't fork the chain → B6.

---

## File Structure

```
agentshield/
  pyproject.toml  alembic.ini  openapi.json
  alembic/env.py  alembic/versions/0001_initial.py …
  src/agentshield/
    settings.py  cli.py
    contracts/{decision,check,scan,events,policy,admin,errors}.py
    db/{engine,models,tenant_tx,partitions}.py
    tenants/{keys,crypto,passwords,jwt,registry,urls,auth}.py
    gateway/{app,errors,idempotency,limits}.py
    gateway/routes/{anthropic,openai,models,check,scan,token,approvals_agent,auth,admin_*}.py
    proxy/{upstream,anthropic_stream,openai_stream,sse,sessions,untrusted}.py
    policy/{loader,evaluator,budgets,approvals,decide,notifier}.py
    scan/{normalizer,rules,rules_default.yaml,classifier,judge,pipeline,risk,action_check}.py
    audit/{redact,emitter,spool,worker,chain,read,replay,retention}.py
    testing/stub_upstream.py
  tests/{unit,integration,security,perf,fixtures}/
```

---

# STAGE 1

### Task B1: Scaffold, settings, shared contracts, CI

**Files:**
- Create: `agentshield/pyproject.toml`, `src/agentshield/settings.py`, `src/agentshield/contracts/{decision,check,scan,events,policy,errors}.py`, `.github/workflows/ci.yml`
- Test: `tests/unit/test_contracts.py`

**Interfaces:**
- Produces: `Decision(StrEnum)`; `EffectTag(StrEnum)` (six values); `CheckRequest` (incl. optional `context.end_user`), `CheckResponse`, `Finding` (api §A.4.1); `ScanRequest`, `ScanResult` (arch §2.2); `AuditEvent` (arch §4.2: envelope fields == `audit_events` columns, incl. `reason`, `end_user`, `summary`, `payload_sha256`) and `EventType(StrEnum)` with exactly the canonical list in arch §4.2; `Problem` (api §A.5); `new_trace_id() -> str` (`t-` + ULID); `SLUG_RE`; `Settings` (env prefix `AGENTSHIELD_`: `database_url`, `redis_url`, `master_key`, `key_pepper`, `jwt_secret`, `signup`, `allow_private_upstreams`, `classifier`, `classifier_dir`).

- [ ] **Step 1: Write failing tests** — `test_decision_has_exactly_three_values`; `test_effect_tags_are_the_six_spec_values`; `test_check_request_accepts_prompt_section9_example` (paste the JSON from api §A.4.1, validate, re-serialize equal); `test_check_request_forbids_extra_fields`; `test_trace_ids_are_prefixed_and_time_sortable`; `test_slug_regex_accepts_email_reader_01_rejects_uppercase_and_leading_dash`; `test_problem_serializes_with_problem_json_fields`; `test_event_type_enum_matches_spec_list`; `test_audit_event_fields_match_audit_events_columns` (compares to a constant list mirrored by B2's migration test).
- [ ] **Step 2: Run** `pytest tests/unit/test_contracts.py -v` → FAIL (import errors).
- [ ] **Step 3: Implement** contracts (pydantic `ConfigDict(extra="forbid")` on inputs) and settings; `pyproject.toml` with ruff (line 100), mypy strict, pytest markers `integration, security, perf, slow`; CI workflow: ruff, mypy, unit; integration job with `postgres:18` and `redis:7` services.
- [ ] **Step 4: Run** tests + `ruff check` + `mypy --strict src` → PASS.
- [ ] **Step 5: Commit** `feat(backend): scaffold, settings and shared contracts`.

### Task B2: Database schema, RLS, roles, partitions

**Files:**
- Create: `src/agentshield/db/{engine,models,tenant_tx,partitions}.py`, `alembic/env.py`, `alembic/versions/0001_initial.py`
- Test: `tests/integration/test_schema.py`, `tests/security/test_rls.py`

**Interfaces:**
- Consumes: `Settings.database_url`.
- Produces: SQLAlchemy models for every table in db §B.3; `@asynccontextmanager async def tenant_tx(engine, tenant_id: UUID) -> AsyncIterator[AsyncSession]` (opens a transaction and runs `set_config('app.tenant_id', :t, true)` first); `async def ensure_partitions(engine, months_ahead: int = 3) -> list[str]`; SECURITY DEFINER functions `private.resolve_agent_key`, `private.resolve_login`, `private.create_tenant`, `private.tenants_with_due_approvals` (db §B.2); roles per db §B.2; `CLI: agentshield db upgrade | ensure-partitions`.

- [ ] **Step 1: Write failing tests** — `test_upgrade_creates_all_tables_and_downgrade_removes_them`; `test_every_tenant_table_has_forced_rls_and_tenant_policy` (introspect `pg_class.relrowsecurity/relforcerowsecurity`); `test_rls_hides_other_tenant_rows` (parametrized over all tenant tables); `test_rls_rejects_insert_for_other_tenant`; **`test_missing_tenant_setting_returns_zero_rows`** (Review Focus 3); `test_app_role_cannot_update_or_delete_audit_events`; `test_policy_versions_are_immutable`; `test_no_unindexed_foreign_keys` (the query from [pg:schema-foreign-key-indexes] returns no rows); `test_uuidv7_ids_sort_by_insert_order`; `test_ensure_partitions_is_idempotent`; `test_resolve_agent_key_returns_only_listed_columns`.
- [ ] **Step 2: Run** `pytest -m integration tests/integration/test_schema.py tests/security/test_rls.py` → FAIL.
- [ ] **Step 3: Implement** the migration exactly per db §B.3 (DDL, partial and composite indexes, triggers, RLS helper applied in a loop, grants, `statement_timeout`/`idle_in_transaction_session_timeout` on the app role); `tenant_tx`; `ensure_partitions` (+ default partition).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(db): schema with RLS, append-only partitioned audit tables and least-privilege roles`.

### Task B3: Tenants, users, agents, keys, upstreams, auth

**Files:**
- Create: `src/agentshield/tenants/{keys,crypto,passwords,jwt,registry,urls,auth}.py`, `src/agentshield/gateway/{app,errors,idempotency}.py`, `src/agentshield/gateway/routes/{auth,token,admin_agents,admin_upstreams,admin_users,admin_settings}.py`, `src/agentshield/contracts/admin.py`
- Test: `tests/unit/test_keys.py`, `test_crypto.py`, `test_urls.py`, `test_jwt.py`, `tests/integration/test_admin_api.py`, `tests/security/test_tenant_isolation.py`, `tests/security/test_route_roles.py`

**Interfaces:**
- Consumes: B1 contracts, B2 `tenant_tx`, security-definer functions.
- Produces:
  - `issue_secret(prefix: str, pepper: bytes) -> IssuedSecret(plaintext, hash, prefix16)`; `verify_secret(pepper, presented, stored_hash) -> bool` (constant time).
  - `encrypt_secret(master_key, plaintext) -> bytes`; `decrypt_secret(master_key, blob) -> str`.
  - `hash_password(pw) -> str`; `verify_password(hash, pw) -> bool` (argon2id m=64MiB t=3 p=1).
  - `mint_agent_jwt(tenant_id, agent_slug, secret, ttl=900) -> str`; `verify_agent_jwt(token, secret) -> AgentClaims`.
  - `validate_outbound_url(url: str, *, allow_private: set[str]) -> str` raising `UnsafeURL` (https only unless host allow-listed; DNS-resolve and reject private/loopback/link-local/metadata; used again at connect time).
  - `@dataclass(frozen=True) TenantContext(tenant_id: UUID, actor: Literal["agent","user"], actor_id: UUID, agent_slug: str | None, role: Role | None)`.
  - FastAPI deps: `agent_ctx` (accepts `Authorization: Bearer ask_live_…`, `x-api-key`, or agent JWT), `user_ctx(min_role)` (session cookie + CSRF, or `asu_` token).
  - Routes: `/v1/signup`, `/v1/auth/{login,logout,me}`, `/v1/token`, `/v1/admin/{users,agents,agents/{slug}/keys,…/revoke,…/rotate,…/snippet,upstreams,upstreams/{id}/test,settings}` per api §A.3; RFC 9457 handler; `Idempotency-Key` middleware (Redis `idem:` keys).

- [ ] **Step 1: Write failing tests** —
  - keys: plaintext matches `^ask_live_[A-Za-z0-9_-]{32}$`; two issues differ; wrong/revoked/expired key fails; rotation overlap honoured.
  - crypto roundtrip; wrong master key raises.
  - urls (Review Focus 4): rejects `http://169.254.169.254/`, `http://[::1]`, `https://10.0.0.5`, a hostname whose DNS (monkeypatched resolver) returns `192.168.1.2`, `ftp://…`; accepts `https://api.openai.com/v1`; accepts `http://vllm:8000` only when `vllm` is in `allow_private`.
  - auth: 5 bad logins lock the account for 15 min; unknown-email and wrong-password responses are identical; cookie flags `HttpOnly; Secure; SameSite=Lax`; unsafe method without `X-CSRF-Token` → 403.
  - isolation (parametrized over **every** control-plane route with a path id): tenant A user + tenant B id → **404**; `tenant_id` sent in body/query is rejected (422, extra field).
  - roles (route table): every `/v1/admin/**` route declares a role; viewer gets 403 on admin-only routes; an agent key on any control-plane route → 401.
  - `test_upstream_read_never_contains_key_material` and `test_logs_never_contain_provider_key` (caplog grep).
  - `test_issue_key_returns_plaintext_once_then_only_prefix`; `test_rotate_sets_old_key_expiry_to_overlap_and_returns_new_plaintext_once`.
  - idempotency: same key + same body → same response; same key + different body → 409 `idempotency_conflict`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(auth): tenants, agents, keys, encrypted upstreams and hardened auth`.

### Task B4: Upstream adapters and non-streaming proxy

**Files:**
- Create: `src/agentshield/proxy/{upstream,sessions,untrusted}.py`, `src/agentshield/gateway/routes/{anthropic,openai,models}.py`, `src/agentshield/testing/stub_upstream.py`
- Test: `tests/integration/test_proxy_nonstream.py`, fixtures `tests/fixtures/{anthropic,openai}/*.json`

**Interfaces:**
- Consumes: `agent_ctx`, `decrypt_secret`, `validate_outbound_url`.
- Produces: `class Upstream(Protocol)` with `async complete(body: dict, headers: Mapping[str,str]) -> UpstreamResponse` and `stream(...) -> AsyncIterator[bytes]`; `AnthropicUpstream`, `OpenAICompatUpstream` (connect 5 s / read 120 s, 10 MB cap, no redirects); `resolve_session(ctx, headers, messages) -> SessionRef(id: UUID, key: str, user_request: str, end_user: str | None)` (`end_user` from `X-AgentShield-User`); `extract_untrusted(api: Literal["anthropic","openai"], body) -> list[UntrustedPart]` (tool results + `X-AgentShield-Untrusted` marked parts); `ProxyHooks` protocol with `before_upstream(...)` and `judge_tool(...)` — **identity implementations in this task**; `stub_upstream.app` (FastAPI app that replays scripted responses in either format, streaming or not).

- [ ] **Step 1: Write failing tests** — stored key forwarded to upstream and absent from the client response; passthrough `X-Upstream-Authorization` forwarded, never stored or logged; missing/invalid key → 401 in the provider's error shape; allowed response is byte-identical to the upstream's; `X-AgentShield-Trace` header present; session from `X-AgentShield-Session` else derived hash; `user_request` = first user message text; `extract_untrusted` returns Anthropic `tool_result` blocks and OpenAI `role: tool` messages, not user/system messages; upstream 500 → 502 `upstream_error`, timeout → 504; body > 2 MB → 413; `/v1/models` lists the agent's aliases.
- [ ] **Step 2–4:** fail → implement → pass.
- [ ] **Step 5: Commit** `feat(proxy): anthropic and openai-compatible non-streaming proxy`.

### Task B5: Streaming proxy with tool-call buffer and rewrite

**Files:**
- Create: `src/agentshield/proxy/{sse,anthropic_stream,openai_stream}.py`
- Modify: `gateway/routes/{anthropic,openai}.py`
- Test: `tests/unit/test_sse.py`, `tests/unit/test_rewrite_anthropic.py`, `tests/unit/test_rewrite_openai.py`, `tests/integration/test_proxy_stream.py` with recorded fixtures (≥ 3 per format)

**Interfaces:**
- Produces: `@dataclass ToolCall(id: str, name: str, arguments: dict[str, Any] | None, raw_arguments: str)`; `ToolJudgement = Allow | Replace(text: str)`; `async def rewrite_anthropic(stream: AsyncIterator[bytes], judge: Callable[[ToolCall], Awaitable[ToolJudgement]]) -> AsyncIterator[bytes]`; `rewrite_openai(...)` same signature; `def rewrite_anthropic_message(body: dict, judge) -> dict` and `rewrite_openai_message(...)` for non-streaming (replaces B4's identity hook).

- [ ] **Step 1: Write failing tests** — unchanged stream when all tools allowed; blocked tool replaced by a text block with the exact text, block indexes renumbered, `stop_reason` → `end_turn`; **mixed turn keeps text + allowed tool** and keeps `stop_reason=tool_use` (Review Focus 2); **1-byte chunking** over all fixtures: the blocked tool's name and argument values never appear in output bytes (Review Focus 1); `input_json_delta` split mid-token; OpenAI `arguments` string concatenated across deltas then parsed; malformed tool JSON → `arguments=None`, `raw_arguments` kept, judged (judge decides; B10 fail rule blocks it); text deltas are forwarded before the tool block completes (latency); usage fields preserved.
- [ ] **Step 2–4:** fail → implement → pass.
- [ ] **Step 5: Commit** `feat(proxy): streaming tool-call buffering and rewrite for both formats`.

### Task B6: Redaction, emitter, spool, worker, hash chain

**Files:**
- Create: `src/agentshield/audit/{redact,emitter,spool,worker,chain,read}.py`, `src/agentshield/gateway/routes/admin_events.py` (minimal `GET /v1/admin/events` for the stage-1 gate), CLI `verify-chain`, `worker` entrypoint
- Modify: proxy routes (emit `request.received`, `content.untrusted`, `model.response`, `tool.requested`, `tool.rewritten`)
- Test: `tests/unit/test_redact.py`, `test_chain.py`, `test_spool.py`, `tests/integration/test_audit_pipeline.py`

**Interfaces:**
- Produces: `redact(value: Any) -> Redacted(value, kinds: list[str])` (patterns: `sk-…`, `sk-ant-…`, `AKIA…`, `ghp_…`/`github_pat_…`, `xox[bp]-…`, JWTs, bearer values, `Authorization`/`x-api-key` keys, emails, Luhn-valid card numbers → `[REDACTED:<kind>:<sha8>]`); `class Emitter` with `async emit(event: AuditEvent, payload: Mapping[str, Any]) -> None` (redact → cap 64 KB → sha256 → XADD; on Redis error → `Spool` (bounded 10k, disk-backed JSONL) and later `audit.gap`); `canonical_json(obj) -> bytes`; `compute_hash(prev: bytes, envelope: Mapping[str, Any]) -> bytes` (envelope = all `audit_events` columns except `prev_hash`, `hash`); `GENESIS = sha256(b"agentshield-genesis-v1")`; `async def run_worker(settings, *, batch: int = 500) -> None`; `async def verify_chain(engine, tenant_id) -> ChainReport(ok, first_bad_seq, checked)`.

- [ ] **Step 1: Write failing tests** — each redaction pattern + nested structures + non-secrets untouched; chain: genesis, tamper detection reports the right `first_bad_seq`; purging a payload row does **not** break `verify_chain`; integration: `test_request_carrying_sk_key_leaves_no_secret_in_redis_or_postgres`; **`test_concurrent_workers_same_tenant_single_chain`** (Review Focus 8); **`test_redis_down_spools_then_emits_audit_gap`** (Review Focus 7); `test_oversize_payload_truncated_flag_and_sha`; `test_stage1_gate_events_visible_via_admin_events`.
- [ ] **Step 2–4:** fail → implement → pass (worker per db §B.5 advisory lock).
- [ ] **Step 5: Commit** `feat(audit): redacted, hash-chained, append-only audit pipeline`.

**Stage 1 gate:** `pytest -m "not slow"` green; manual: one stream + one non-stream request per format → events listed by trace; `agentshield verify-chain --tenant acme` exits 0. Push.

---

# STAGE 2

### Task B7: Policy model and loader

**Files:**
- Create: `src/agentshield/policy/loader.py`, extend `contracts/policy.py`, `gateway/routes/admin_policies.py`
- Test: `tests/unit/test_policy_loader.py`, `tests/integration/test_policy_versions_api.py`

**Interfaces:**
- Produces: `PolicyDoc` (`version`, `agent`, `default: Literal["deny"]`, `budgets`, `scopes: dict[str, list[str]]`, `tag_defaults: dict[EffectTag, Decision]`, `rules: list[Rule]`), `Rule` (`id, effect, tool, effect_tag, when, reason`), `Condition` (`arg | session.risk_score`, `op`, `value`) with `all`/`any`; `parse_policy(yaml_text) -> CompiledPolicy` (regex/glob precompiled) raising `PolicyError(errors: list[LineError])`; routes for versions/list/get/activate per api §A.3 (activation with `If-Match`).

- [ ] **Step 1: Write failing tests** — the arch §2.1 samples (rules + scopes + tag_defaults) parse; duplicate rule id, `default: allow`, unknown operator, uncompilable regex, undefined scope reference, unknown effect tag → errors **with line numbers**; versions immutable (re-POST same number → 409); activation without/with stale `If-Match` → 428/412; activation affects only that agent; a viewer can read but not create.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(policy): versioned yaml policies with scopes and tag defaults`.

### Task B8: Evaluator

**Files:**
- Create: `src/agentshield/policy/evaluator.py`
- Test: `tests/unit/test_evaluator.py`, `tests/perf/test_evaluator_latency.py`

**Interfaces:**
- Produces: `SessionState(risk_score: float, approved: frozenset[tuple[str, str]])`; `Evaluation(decision, rule_id, reason, matched: tuple[str, ...], effect_tag: EffectTag)`; `evaluate(policy: CompiledPolicy, tool: str, arguments: Mapping[str, Any] | str | None, session: SessionState) -> Evaluation` (pure; parses string arguments; never raises — internal error → `block`/`evaluator-error` unless tag is `read`); `args_hash(arguments) -> str` (sha256 of canonical JSON).

- [ ] **Step 1: Write failing tests** (table-driven) — no rule → `default-deny`; `tag_defaults` applied when no rule matches a tagged tool; block > ask > allow; every operator incl. `in_scope`/`not_in_scope`, `domain_in`/`not_domain_in` (case-insensitive, subdomains not matched unless `*.acme.com`); dotted paths; missing argument → condition false; `"*"` tool; risk rule at 0.8; **string / malformed / None arguments** (Review Focus 5); approved allowance converts `ask` → `allow` but never overrides `block`. Perf: 200-rule policy × 10k random calls, p95 < 20 ms (prints measured value).
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(policy): default-deny evaluator`.

### Task B9: Budgets and rate limits

**Files:**
- Create: `src/agentshield/policy/budgets.py`, `src/agentshield/gateway/limits.py`
- Test: `tests/unit/test_budgets.py` (fakeredis), `tests/integration/test_rate_limits.py`

**Interfaces:**
- Produces: `BudgetTracker.check(tenant_id, agent_slug, budgets) -> BudgetStatus(ok, exceeded: Literal["cost","calls","tokens","rpm"] | None)`; `BudgetTracker.record(tenant_id, agent_slug, tokens, cost_micro_usd) -> None` (Lua script, atomic); `BudgetUnavailable`; `price_micro_usd(model_entry: ModelMapEntry, usage) -> int` using `input_/output_micro_usd_per_mtok` from the upstream's `model_map` (api §A.4.4; missing prices → 0 and one `budget.price_missing` warning per day); hourly mirror to `budget_counters`; per-key rate limiter middleware with `RateLimit-*` headers and 429 in provider shape on proxy routes.
- [ ] **Step 1: Write failing tests** — each limit trips; UTC-midnight reset; 100 concurrent `record` calls sum exactly; Redis error → `BudgetUnavailable`; 429 includes `Retry-After`.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(policy): per-agent budgets and rate limits`.

### Task B10: `decide_tool_call`, proxy enforcement, `/v1/check`

**Files:**
- Create: `src/agentshield/policy/decide.py`, `gateway/routes/check.py`
- Modify: proxy routes (plug `decide_tool_call` into the B5 judge)
- Test: `tests/integration/test_policy_proxy.py`, `tests/integration/test_check_api.py`

**Interfaces:**
- Consumes: B5 judge hook, B8 `evaluate`, B9 tracker, B6 emitter.
- Produces: `async def decide_tool_call(ctx: TenantContext, session: SessionRef, call: ToolCall, *, trace_id: str) -> CheckResponse` (loads active policy (cached by `(agent, version)`), session risk, budgets; applies `mode: monitor`; applies fail rule on any internal error; emits `tool.requested`, `policy.decision`); `POST /v1/check` (validates `agent_id`/`tenant` against the credential → 403 `credential_mismatch`).
- [ ] **Step 1: Write failing tests** — **`test_stage2_gate_forbidden_tool_blocked`** (stub model emits `send_email` to `x@unknown.com` → client gets block text, `stop_reason=end_turn`, audit has `rule_id=deny-external-send`); `read_email` passes; monitor mode passes and records `would_have=block`; budget exceeded → block `budget-exceeded`; check API returns the §9 response shape; unknown tool → `default-deny`; **Redis down → `send_email` blocked, `read_email` allowed** (Review Focus 7); evaluator exception → fail rule by tag; mismatched `agent_id` → 403.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(policy): enforce policies in proxy and check api`.

### Task B11: Approvals

**Files:**
- Create: `src/agentshield/policy/{approvals,notifier}.py`, `gateway/routes/{approvals_agent,admin_approvals}.py`
- Test: `tests/unit/test_approvals.py`, `tests/integration/test_approval_flow.py`

**Interfaces:**
- Produces: `request_approval(ctx, session, call, evaluation, trace_id) -> Approval`; `decide_approval(user_ctx, approval_id, approve: bool, note: str | None, if_match: str) -> Approval`; `expire_due() -> int` (SKIP LOCKED, db §B.5); `class Notifier(Protocol)` + `WebhookNotifier` (POST JSON `{approval_id, agent, tool, arguments_redacted, rule_id, expires_at, dashboard_url}`, URL validated by `validate_outbound_url`, 3 retries); `GET /v1/approvals/{id}` (agent), `GET /v1/admin/approvals`, `POST /v1/admin/approvals/{id}/decision`; long-poll on `/v1/check` with `wait_seconds` via Redis pub/sub.
- [ ] **Step 1: Write failing tests** — `ask` → pending row + webhook with redacted raw args and **no model prose**; proxy `ask` rewrite text exact; approve → allowance key set (900 s) and the identical call in the same session is allowed, in a different session is not; deny/expire → block; 300 s expiry with a fake clock; an agent credential cannot decide (401 on control plane); viewer 403, analyst OK; second decision 409; stale `If-Match` 412; webhook failure → `approval.notify_failed` event, approval still pending; long-poll returns early on decision.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(policy): human approvals with webhook, expiry and long-poll`.

**Stage 2 gate:** `test_stage2_gate_forbidden_tool_blocked` green in CI. Push.

---

# STAGE 3

### Task B12: Normalizer

**Files:** Create `src/agentshield/scan/normalizer.py`; Test `tests/unit/test_normalizer.py`, `tests/unit/test_normalizer_properties.py` (hypothesis)

**Interfaces:**
- Produces: `Normalized(text: str, hidden_text: str, transforms: list[str], offset_map: list[int], truncated: bool, unscannable: bool)`; `normalize(raw: str | bytes, *, max_bytes: int = 200_000) -> Normalized`; `to_original_span(norm, span) -> tuple[int, int]`.
- [ ] **Step 1: Write failing tests** — zero-width + bidi stripped and listed in `transforms`; NFKC folds full-width text; HTML comments and `display:none` / `visibility:hidden` / `font-size:0` / same-color text moved to `hidden_text`; base64 and hex blobs ≥ 24 chars decoded to depth 2; homoglyph mixed-script words flagged; empty input, invalid UTF-8 and 5 MB input return a result (never raise); property test: `to_original_span` always lands inside the original string.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(scan): normalizer for hidden and encoded content`.

### Task B13: Rule signatures with hot reload

**Files:** Create `src/agentshield/scan/{rules,rules_default.yaml}`, `gateway/routes/admin_scan_rules.py`; Test `tests/unit/test_rules.py`, `tests/integration/test_rules_reload.py`

**Interfaces:**
- Produces: `RuleHit(rule_id, category, weight, span, text, hidden: bool)`; `RuleSet(version: int, rules)`; `load_ruleset(yaml_text) -> RuleSet`; `run_rules(norm, ruleset) -> list[RuleHit]`; `rule_score(hits) -> float` (max weight + 0.1 per extra distinct category, cap 1.0); `RuleStore` (platform default from file, tenant override from `scan_rule_sets`, re-checked every 60 s and on `POST /v1/admin/scan-rules/reload`).
- [ ] **Step 1: Write failing tests** — ≥ 12 attack phrasings hit with correct spans (ignore previous instructions, forward all … to, reveal your system prompt, you are now, send the contents to http…, new instructions:, etc.); **hard negatives stay < 0.35** (quoted training text, "please forward this to finance") (Review Focus 6); hits inside `hidden_text` marked `hidden=True` and weighted +0.1; every rule in `rules_default.yaml` has a positive and a negative fixture (test iterates the file); reload swaps the version atomically and the version appears on scan events.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(scan): weighted signature rules with hot reload`.

### Task B14: Classifier adapters

**Files:** Create `src/agentshield/scan/classifier.py`, `scripts/export_classifier_onnx.py`, `docs/superpowers/specs/classifier-selection.md`; Test `tests/unit/test_classifier.py`, `tests/perf/test_classifier_latency.py` (`slow`)

**Interfaces:**
- Produces: `Classifier(Protocol).score(text: str) -> float`; `OnnxClassifier(model_dir: Path, positive_label: str)` (tokenizer + onnxruntime, INT8, 512-token windows with 64 overlap, returns max); presets `PROTECTAI_V2` (default) and `PROMPT_GUARD_2_22M` (opt-in, user-downloaded); `StubClassifier`; `NullClassifier` + `degraded=True`; `load_classifier(settings) -> Classifier`.
- [ ] **Step 1: Write failing tests** — stub deterministic; tiny fixture ONNX model in `tests/fixtures/` returns values in [0,1]; long text windowed; missing model dir → degraded flag, `/readyz` reports `classifier: degraded`, and an `error` event — never silently "clean".
- [ ] **Step 2: Measure** both presets on the reference CPU (≤ 2 KB inputs, 200 samples): p50/p95 latency, RSS, file size; record in `classifier-selection.md` with licence notes (arch §7.4). The perf test prints values and fails only if p95 > 250 ms.
- [ ] **Step 3–4:** implement → pass. **Step 5: Commit** `feat(scan): onnx classifier adapters (protectai v2 default, prompt guard 2 optional)`.

### Task B15: Judge, pipeline, risk, action check, `/v1/scan`, prompt marking

**Files:** Create `src/agentshield/scan/{judge,pipeline,risk,action_check}.py`, `gateway/routes/scan.py`; Modify proxy `before_upstream` hook and `policy/decide.py` (risk input + action check); Test `tests/unit/test_pipeline.py`, `test_risk.py`, `test_action_check.py`, `test_judge.py`, `tests/integration/test_scan_api.py`, `tests/integration/test_proxy_scanning.py`

**Interfaces:**
- Produces: `scan(content: Content, ctx: ScanContext) -> ScanResult`; `judge(text: str, upstream: Upstream, model: str, timeout: float = 1.5) -> JudgeVerdict` (no `tools` field in the request; content inside `<data>` delimiters; strict JSON parse; anything else → suspicious 0.5); `update_risk(r: float, verdict: str, confidence: float) -> float`; `action_in_scope(user_request: str, call: ToolCall, allowed_domains: set[str]) -> ActionCheck(ok: bool, reason: str)` (feeds +0.2 risk when not ok); `sanitize(text, findings, mode) -> str`; proxy marks untrusted parts with `<untrusted source=… id=…>` and the system addendum (opt-out per agent).
- [ ] **Step 1: Write failing tests** — < 0.35 clean, no judge; 0.35–0.80 judge exactly once; ≥ 0.80 malicious, no judge; judge timeout / non-JSON → suspicious 0.5, content passes; sanitize replaces span with `[removed by AgentShield]`, quarantine fallback without span; risk monotonic under repeated suspicious scans; judge request has no `tools` key; action check flags an address absent from request and allow-list; `/v1/scan` empty and 5 MB → 200 / 413 per api §A.7; proxy: `tool_result` scanned and wrapped; **the email attack raises session risk ≥ 0.8 so `tighten-on-risk` blocks the next effectful call**.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(scan): layered injection pipeline, judge and session risk`.

*(Stage 3 closes with E1 in the sdk-demo-eval plan.)*

---

# STAGE 4 (backend)

### Task B16: OpenAPI contract, observability and API hardening suite (runs after B17)

**Files:** Create `agentshield/openapi.json` (generated), `scripts/export_openapi.py`, `src/agentshield/observability.py`, `tests/security/test_owasp_api.py`, `tests/contract/test_openapi_snapshot.py`, `tests/integration/test_observability.py`, CI job `schemathesis`; Modify `gateway/app.py` (security headers, CORS, docs off in prod, OTel + metrics), `audit/worker.py` (metrics)

**Interfaces:**
- Produces: committed `openapi.json` (consumed by F1 and E2); CI job running `schemathesis run agentshield/openapi.json --checks all` against the app with seeded data; `setup_observability(app, settings)` — OpenTelemetry spans (FastAPI, httpx, SQLAlchemy, Redis instrumentation) whose trace id is linked to the AgentShield `trace_id` (stored as `otel_span_id` on events), OTLP exporter optional by env; Prometheus `/metrics` (internal network only) with `agentshield_decisions_total{decision,module}`, `agentshield_scan_latency_seconds{layer}`, `agentshield_policy_eval_seconds`, `agentshield_audit_lag_seconds`, `agentshield_approvals_pending`, `agentshield_stream_pending`; `/readyz` reports DB, Redis, classifier (`degraded`), worker lag.
- [ ] **Step 1: Write failing tests** — snapshot equals generated spec; one test per row of api §A.6 not already covered (security headers present, no wildcard CORS, `/docs` disabled when `env=prod`, response size cap on upstream, `statement_timeout` active); every Read model lacks `key_hash`, `key_ciphertext`, `password_hash`; end-to-end perf: rule-only check p95 < 200 ms against stub upstream (prints value); observability: a proxied request produces spans for gateway → policy → upstream with the same trace, `/metrics` exposes every metric name above and is refused from outside the internal network, `/readyz` turns 503 when Redis is down.
- [ ] **Step 2–4:** fail → implement → pass; Schemathesis finds no 5xx.
- [ ] **Step 5: Commit** `feat(api): committed openapi contract and owasp api hardening tests`.

### Task B17: Search, timeline, replay, simulator, incidents, alerts, stats, export, retention, seed

**Files:** Create `src/agentshield/audit/{replay,retention}.py`, `gateway/routes/{admin_sessions,admin_incidents,admin_alerts,admin_stats}.py`, CLI `seed-demo`, `retention-run`; extend `audit/read.py`; Test `tests/unit/test_replay.py`, `tests/integration/test_replay_api.py`, `tests/integration/test_retention.py`, extend `tests/security/test_tenant_isolation.py`

**Interfaces:**
- Produces: `GET /v1/admin/events` (full filters incl. `user`, keyset on `(ts, seq)`), `GET /v1/admin/sessions[/{id}[/timeline]]`, `replay_session(ctx, session_id, *, policy_version: int | None) -> ReplayResult(steps, changed: list[StepDiff])` (re-evaluates recorded `tool.requested` with the chosen version; model text shown as recorded), `POST …/replay`, `POST /v1/admin/agents/{slug}/policy/simulate`, incidents CRUD, `GET /v1/admin/alerts` (derived from blocked / malicious / expired / budget / chain events), `GET /v1/admin/stats/overview`, `GET …/export.json` (events + chain head + verification), `retention_run(now)` (payload purge, partition checkpoint + drop, incident archive), `agentshield seed-demo`.
- [ ] **Step 1: Write failing tests** — timeline ordered by `seq` and grouped by `trace_id`; replay with the active version reproduces recorded decisions; replay with a relaxed version lists the changed step; simulate over `since=7d` counts changes; viewer gets `payload` redacted-only and cannot replay; isolation test covers all new routes; export contains chain head and `verified: true`; retention keeps incident payloads, purges others after 30 d, never drops a partition younger than 180 d, writes `audit.checkpoint`; `seed-demo` is idempotent.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(audit): timeline, replay, simulator, incidents, alerts and retention`.

---

## Self-Review

- **Spec coverage:** observability (arch §8.3) → B16; `reason`/`end_user` on events → B1, B6, B17; key rotation → B3; arch §2.1 → B7–B11; §2.2 → B12–B15 (+E1); §2.5 → B6, B17; §3.1 proxy → B4, B5, B10, B15; §3.3 keys → B3, B4; api §A.1–A.8 → B3, B16 (+ per-route tests in each task); db §B.1–B.9 → B2, B6, B17; retention → B17; tags/scopes/hot reload → B7, B8, B13; classifier decision → B14. M3/M4/MCP proxy: tables only (B2), by design.
- **Type consistency:** `TenantContext`, `SessionRef`, `ToolCall`, `ToolJudgement`, `CompiledPolicy`, `SessionState`, `Evaluation`, `CheckResponse`, `Normalized`, `RuleHit`, `ScanResult`, `Emitter` are defined once (B1–B15) and referenced by these names.
- **Review Focus:** all eight items have a named test in their owning task.
- **Proportion:** signatures, exact values and test names only; no function bodies except the formulas the spec fixes.
