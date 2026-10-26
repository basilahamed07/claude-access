# AgentShield v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build AgentShield stages 1–4: a multi-tenant universal agent gateway with permission control, a prompt-injection firewall, a tamper-evident audit log with replay, a dashboard, a Python SDK and an email-agent attack demo.

**Architecture:** One FastAPI gateway (Anthropic + OpenAI proxy, `/v1/check`, `/v1/scan`, admin API) runs M1 policy and M2 scanning in-process behind Python interfaces. Every step emits a redacted event to a Redis Stream; a separate worker is the only writer of the hash-chained, append-only Postgres `audit_events`. A React dashboard reads the admin/audit API.

**Tech Stack:** Python 3.12, FastAPI, httpx, pydantic v2, SQLAlchemy 2 async + Alembic, PostgreSQL 16, Redis 7, PyYAML, cryptography (Fernet), argon2-cffi, onnxruntime + tokenizers, pytest + pytest-asyncio + respx, ruff, mypy; React + Vite + TypeScript; Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-26-agentshield-design.md` (executors read both; section references below are `spec §n`).

## Global Constraints

- Python **3.12**; all code typed; `ruff check` and `mypy --strict agentshield/src` pass before every commit.
- **Default deny:** a tool call matching no rule is blocked with `rule_id="default-deny"` (spec §2.1).
- **Precedence:** `block` > `ask` > `allow` (spec §2.1).
- `tenant_id` is derived from the credential, never from client input; every repository function takes a `TenantContext` (spec §8.1).
- Agent keys: `ask_live_` + 32 url-safe random chars; stored only as `HMAC-SHA256(pepper, key)`; shown once (spec §4.1).
- Provider keys: Fernet-encrypted at rest, master key from `AGENTSHIELD_MASTER_KEY`; never logged, never in events (spec §8.2).
- Redact **before** publishing any event; payload cap **64 KB** with `payload_truncated` + `payload_sha256` (spec §2.5).
- `audit_events` is append-only (trigger rejects UPDATE/DELETE); `hash = sha256(prev_hash || canonical_json(event))`, per tenant (spec §4.2).
- Decision enum exactly `allow | block | ask`; agent id `agt_<ulid>`; trace id `t-<ulid>` (spec §3).
- Blocked tool blocks are replaced with text `Action blocked by AgentShield: <reason> (rule <id>, trace <trace_id>)`; when all tool blocks are replaced, `stop_reason` → `end_turn` / `finish_reason` → `stop` (spec §3.1).
- Approvals expire after **300 s** → `expired` (counts as deny); an approved `(session, tool, args_hash)` is allowed for **900 s** (spec §2.1).
- Judge band **0.35–0.80**, timeout **1.5 s**; timeout → `suspicious`, confidence 0.5 (spec §2.2).
- Fail rule: `write|external|financial` and untagged tools fail closed; `read` may fail open with a logged `error` event; text always passes (spec §8.6).
- Latency budget [unmeasured targets]: policy eval p95 < 20 ms; rules path total < 200 ms (spec §3).
- The README/eval report may only quote numbers the eval run printed.
- Commit after each task; branch `claude/elegant-maxwell-ipbatc`; no PRs unless asked.

## Review Focus

Inputs and conditions the spec implies but no single feature test would exercise; each has a pinning test in the owning task (named in brackets).

1. **Tool-call split across stream chunks** (one byte at a time, or `input_json_delta` split mid-token) must never leak a blocked call. [Task 5]
2. **Mixed turn:** a response with text + one allowed + one blocked tool call keeps the allowed one and the text. [Task 5]
3. **Empty / non-UTF-8 / 5 MB content** sent to `/v1/scan` returns a verdict (`unscannable`/`truncated`), never a 500. [Tasks 12, 15]
4. **Benign text that quotes attack phrases** ("security training: attackers write 'ignore previous instructions'") must not be blocked above the FPR target. [Tasks 13, 16]
5. **Unknown tool name / missing arguments / `arguments` as a JSON string vs object** (OpenAI sends a string) evaluate safely: unknown → default-deny, not an exception. [Tasks 8, 10]
6. **Cross-tenant ids** on every admin/audit route return 404. [Task 3, re-asserted in 17]
7. **Redis down** during a request: effectful tools blocked, read tools allowed, `error` event spooled. [Tasks 6, 10]
8. **Concurrent first events** for a tenant do not fork the hash chain. [Task 6]

---

## File Structure

| Path | Responsibility |
|---|---|
| `agentshield/pyproject.toml`, `agentshield/src/agentshield/settings.py` | deps, config (env-driven) |
| `…/contracts/` | pydantic models shared by all services: `decision.py`, `check.py`, `events.py`, `policy.py`, `scan.py` |
| `…/db/` | `models.py`, `session.py`, `alembic/versions/*` |
| `…/tenants/` | `registry.py`, `keys.py`, `crypto.py`, `auth.py` (FastAPI deps) |
| `…/gateway/` | `app.py`, `routes_anthropic.py`, `routes_openai.py`, `routes_check.py`, `routes_admin.py`, `upstream.py`, `rewrite.py` (stream buffer), `sessions.py` |
| `…/policy/` | `loader.py`, `evaluator.py`, `budgets.py`, `approvals.py` |
| `…/scan/` | `normalizer.py`, `rules.py`, `rules.yaml`, `classifier.py`, `judge.py`, `pipeline.py`, `risk.py`, `action_check.py` |
| `…/audit/` | `redact.py`, `emitter.py`, `worker.py`, `chain.py`, `replay.py`, `search.py` |
| `…/cli.py` | `verify-chain`, `create-tenant`, `seed-demo` |
| `dashboard/` | React app |
| `sdk/python/agentshield_sdk/` | `client.py`, `guard.py` |
| `demo/email_agent/` | LangGraph agent, mock tools, poisoned mailbox, two runner scripts |
| `eval/` | `datasets/*.jsonl`, `run_eval.py`, `README.md` |
| `deploy/docker-compose.yml` | gateway, worker, postgres, redis, dashboard |

---

# STAGE 1 — Core gateway + audit (gate: every call is logged and viewable)

### Task 1: Scaffold, settings and shared contracts

**Files:**
- Create: `agentshield/pyproject.toml`, `agentshield/src/agentshield/{__init__,settings}.py`, `agentshield/src/agentshield/contracts/{__init__,decision,check,events,policy,scan}.py`
- Test: `agentshield/tests/unit/test_contracts.py`

**Interfaces:**
- Produces: `class Decision(StrEnum)` = `allow|block|ask`; `class CheckRequest`, `class CheckResponse` (fields per spec §2.1 and prompt §9: `agent_id, tenant, session_id, action{tool, arguments}, context{user_request, untrusted_inputs[]}` / `decision, reason, rule_id, risk_score, findings[], approval_id, trace_id, mode`); `class AuditEvent` per spec §4.2 (`schema="agentshield.event/1"`); `new_trace_id() -> str` (`t-<ulid>`), `new_agent_id() -> str` (`agt_<ulid>`); `Settings` (env prefix `AGENTSHIELD_`).

- [ ] **Step 1: Write failing tests** — `test_decision_values` (exactly three members); `test_check_request_roundtrips_prompt_example` (the prompt §9 JSON validates and re-serializes equal); `test_check_request_rejects_unknown_decision`; `test_ids_have_prefixes_and_sort_by_time`; `test_audit_event_requires_trace_and_schema`.
- [ ] **Step 2: Run** `pytest agentshield/tests/unit/test_contracts.py -v` → FAIL (modules missing).
- [ ] **Step 3: Implement** the models and id helpers (ULID via `python-ulid`); `pyproject.toml` with ruff/mypy/pytest config.
- [ ] **Step 4: Run** the tests, `ruff check`, `mypy --strict` → PASS.
- [ ] **Step 5: Commit** `feat: scaffold agentshield package and shared contracts`.

### Task 2: Database schema and migrations

**Files:**
- Create: `…/db/models.py`, `…/db/session.py`, `agentshield/alembic.ini`, `agentshield/alembic/env.py`, `agentshield/alembic/versions/0001_initial.py`
- Test: `agentshield/tests/integration/test_schema.py` (uses a Postgres test container or `AGENTSHIELD_TEST_DSN`)

**Interfaces:**
- Consumes: `Settings.database_url`.
- Produces: SQLAlchemy models for every table in spec §4.1 (including unused `mcp_servers`, `ai_tools_seen`); `async def get_session() -> AsyncIterator[AsyncSession]`; Postgres roles `agentshield_app` (INSERT/SELECT/UPDATE except on `audit_events`) and `agentshield_worker` (INSERT/SELECT on `audit_events`).

- [ ] **Step 1: Write failing tests** — `test_migration_creates_all_tables`; `test_audit_events_update_rejected` (UPDATE and DELETE raise `RaiseException` from the trigger, even for the worker role); `test_app_role_cannot_insert_audit_events`; `test_every_tenant_table_has_tenant_id_column` (introspection loop, excluding `tenants`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** models, the migration (including the trigger function `audit_events_immutable()` and role grants), and indexes from spec §4.1.
- [ ] **Step 4: Run** → PASS; `alembic upgrade head && alembic downgrade base` succeeds.
- [ ] **Step 5: Commit** `feat: postgres schema with append-only audit table`.

### Task 3: Tenants, agents, keys and encrypted provider keys (admin API)

**Files:**
- Create: `…/tenants/{registry,keys,crypto,auth}.py`, `…/gateway/routes_admin.py`, `…/gateway/app.py` (app factory)
- Test: `agentshield/tests/unit/test_keys.py`, `agentshield/tests/unit/test_crypto.py`, `agentshield/tests/security/test_tenant_isolation.py`

**Interfaces:**
- Consumes: Task 1 contracts, Task 2 models.
- Produces:
  - `def issue_agent_key(pepper: bytes) -> tuple[str, bytes, str]` → `(plaintext, hash, prefix)`; `def verify_agent_key(pepper: bytes, presented: str, stored_hash: bytes) -> bool` (constant time).
  - `def encrypt_secret(master_key: bytes, plaintext: str) -> bytes` / `def decrypt_secret(master_key: bytes, blob: bytes) -> str`.
  - `@dataclass(frozen=True) class TenantContext(tenant_id: UUID, actor: Literal["agent","user"], actor_id: str, role: str | None)`.
  - FastAPI deps `agent_context(request) -> TenantContext`, `user_context(request) -> TenantContext` (role-checked).
  - Admin routes: `POST /v1/admin/tenants` (bootstrap token), `POST/GET /v1/admin/agents`, `POST /v1/admin/agents/{id}/keys`, `DELETE …/keys/{key_id}`, `POST /v1/admin/upstreams`.

- [ ] **Step 1: Write failing tests** — keys: plaintext starts with `ask_live_` and is 41+ chars, hash differs per key, wrong key fails, revoked key fails, rotation keeps old key valid only until `expires_at`; crypto: roundtrip, wrong master key raises; isolation (parametrized over **every route in the admin router**): user of tenant A requesting a tenant B resource id gets **404**, and `tenant_id` in the body or query is ignored; `test_provider_key_never_returned_or_logged` (create upstream, GET it, capture logs, assert no plaintext).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** keys/crypto and the registry functions (each takes a `TenantContext`); routes; login endpoint `POST /v1/auth/login` with argon2 + signed cookie session.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: tenant registry, agent keys, encrypted upstream keys`.

### Task 4: Upstream adapters and non-streaming proxy

**Files:**
- Create: `…/gateway/upstream.py`, `…/gateway/routes_anthropic.py`, `…/gateway/routes_openai.py`, `…/gateway/sessions.py`
- Test: `agentshield/tests/integration/test_proxy_nonstream.py` with fixtures `tests/fixtures/{anthropic,openai}/*.json`

**Interfaces:**
- Consumes: `agent_context`, `decrypt_secret`, `new_trace_id`.
- Produces: `class Upstream(Protocol): async def complete(self, body: dict, headers: Mapping[str,str]) -> httpx.Response` and `stream(...) -> AsyncIterator[bytes]`; `AnthropicUpstream`, `OpenAICompatUpstream`; `def resolve_session_id(headers: Mapping[str,str], agent_id: str, first_user_message: str) -> str`; routes `POST /v1/messages`, `POST /v1/chat/completions`; header `X-Upstream-Authorization` for passthrough agents.

- [ ] **Step 1: Write failing tests** (with `respx`) — `test_messages_forwards_with_stored_key` (upstream receives the decrypted key, **client never sees it**); `test_passthrough_key_forwarded_and_not_stored`; `test_missing_or_invalid_ask_key_returns_401`; `test_allowed_response_is_byte_identical_to_upstream`; `test_session_id_from_header_else_hash`; `test_upstream_5xx_is_returned_not_swallowed`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** adapters and routes (no policy yet — a pass-through that mints `trace_id` and resolves the session).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: anthropic and openai-compatible proxy routes`.

### Task 5: Streaming proxy with tool-call buffer and rewrite hook

**Files:**
- Create: `…/gateway/rewrite.py`
- Modify: `…/gateway/routes_anthropic.py`, `…/gateway/routes_openai.py`
- Test: `agentshield/tests/unit/test_rewrite.py`, `agentshield/tests/integration/test_proxy_stream.py` with recorded SSE fixtures

**Interfaces:**
- Produces: `ToolVerdict = Callable[[ToolCall], Awaitable[Decision | Rewrite]]`; `async def rewrite_anthropic_stream(upstream: AsyncIterator[bytes], judge: ToolVerdict) -> AsyncIterator[bytes]`; `async def rewrite_openai_stream(...)`; `@dataclass class Rewrite(text: str)`; `@dataclass class ToolCall(id: str, name: str, arguments: dict[str, Any])`.
- Behavior: text deltas pass immediately; a tool block is buffered from `content_block_start` to `content_block_stop` (OpenAI: by `tool_calls[i].index` until `finish_reason`), judged, then emitted or replaced by a synthetic text block with renumbered indexes; `stop_reason`/`finish_reason` patched per Global Constraints.

- [ ] **Step 1: Write failing tests** — `test_allowed_tool_stream_is_unchanged`; `test_blocked_tool_replaced_by_text_and_stop_reason_end_turn`; `test_mixed_turn_keeps_allowed_tool_and_text` (Review Focus 2); `test_one_byte_chunking_never_leaks_blocked_tool` (Review Focus 1; feed the fixture a byte at a time, assert the blocked tool name/args appear nowhere in the output); `test_input_json_delta_split_mid_token`; `test_openai_arguments_string_parsed_before_judging`; `test_unparsable_tool_json_is_judged_with_raw_string_and_blocked_by_fail_rule`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** a small SSE parser/serializer and the two buffering state machines; judge is injected so this task needs no policy code.
- [ ] **Step 4: Run** → PASS; also run the one-byte test for 3 different fixtures.
- [ ] **Step 5: Commit** `feat: streaming tool-call buffer and rewrite for both APIs`.

### Task 6: Redaction, event emitter, audit worker and hash chain

**Files:**
- Create: `…/audit/{redact,emitter,worker,chain}.py`, `…/cli.py` (`verify-chain`)
- Modify: `…/gateway/routes_*.py` (emit `request.received`, `model.response`, `tool.requested`)
- Test: `agentshield/tests/unit/test_redact.py`, `test_chain.py`, `agentshield/tests/integration/test_audit_pipeline.py`

**Interfaces:**
- Produces: `def redact(value: Any) -> tuple[Any, list[str]]` (returns redacted copy + kinds found); `class Emitter: async def emit(self, event: AuditEvent) -> None` (redact → cap payload → XADD; spools to a bounded queue and later emits `audit.gap` when Redis is down); `def compute_hash(prev_hash: bytes, event: Mapping[str, Any]) -> bytes`; `async def run_worker(settings) -> None`; `async def verify_chain(session, tenant_id) -> ChainReport(ok: bool, first_bad_seq: int | None, checked: int)`; CLI `agentshield verify-chain --tenant <id>` (exit 1 on failure).

- [ ] **Step 1: Write failing tests** — redact: `sk-…`, `AKIA…`, `ghp_…`, bearer tokens, emails, Luhn-valid card numbers, nested dict/list, `Authorization` header values all become `[REDACTED:<kind>:<sha8>]`; non-secrets untouched; chain: genesis hash, tampering one row changes `verify_chain` result with the right `first_bad_seq`; integration: `test_request_with_sk_key_leaves_no_secret_in_redis_or_postgres`; `test_two_workers_concurrent_first_events_do_not_fork_chain` (Review Focus 8; per-tenant advisory lock); `test_redis_down_spools_and_emits_audit_gap` (Review Focus 7); `test_oversize_payload_truncated_with_sha256`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** — chain uses canonical JSON (sorted keys, no whitespace); worker assigns `seq` inside a transaction holding `pg_advisory_xact_lock(hash(tenant_id))`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: redacted audit events with hash-chained append-only log`.

**Stage 1 gate:** run the integration suite plus a manual call through the proxy; `GET /v1/admin/events?trace_id=…` (added in task 17; until then query Postgres) shows every step; `verify-chain` passes.

---

# STAGE 2 — Permission control (gate: the demo agent is blocked from a forbidden tool)

### Task 7: Policy model, YAML loader and versioning

**Files:**
- Create: `…/policy/loader.py`, `…/contracts/policy.py` (extend)
- Modify: `…/gateway/routes_admin.py` (policy version endpoints)
- Test: `agentshield/tests/unit/test_policy_loader.py`

**Interfaces:**
- Produces: `class PolicyDoc` (pydantic; `version`, `agent`, `default: Literal["deny"]`, `budgets`, `rules[]` with `id, effect, tool, effect_tag, when, reason`); `def parse_policy(yaml_text: str) -> PolicyDoc` raising `PolicyError(line, message)`; `POST /v1/admin/policies/{agent}/versions` (stores immutable version, optionally `activate`), `POST …/activate`.

- [ ] **Step 1: Write failing tests** — the spec §2.1 sample parses; duplicate rule ids rejected; `default: allow` rejected; unknown operator rejected with line number; regex that fails to compile rejected; versions are immutable (second POST with same number → 409); activating a version only affects that agent and tenant.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: versioned yaml policies`.

### Task 8: Evaluator

**Files:**
- Create: `…/policy/evaluator.py`
- Test: `agentshield/tests/unit/test_evaluator.py`, `agentshield/tests/perf/test_evaluator_latency.py`

**Interfaces:**
- Consumes: `PolicyDoc`.
- Produces: `@dataclass(frozen=True) class SessionState(risk_score: float, approved_calls: frozenset[tuple[str,str]])`; `@dataclass(frozen=True) class Evaluation(decision: Decision, rule_id: str, reason: str, matched: tuple[str, ...])`; `def evaluate(policy: PolicyDoc, tool: str, arguments: Mapping[str, Any] | str | None, session: SessionState) -> Evaluation` (pure, never raises — internal errors return `block`, `rule_id="evaluator-error"` for tools whose tag is not `read`).

- [ ] **Step 1: Write failing tests** — table-driven: unmatched tool → `default-deny`; block beats allow beats nothing; ask beats allow; each operator (`eq,in,not_in,regex,glob,domain_in,not_domain_in,gt,gte,lt,lte`) true and false; dotted arg paths; `tighten-on-risk` triggers at `risk_score >= 0.8`; `arguments` given as JSON string is parsed (Review Focus 5); missing argument → rule with `when` on it does not match; `"*"` tool glob; approved-call allowance (tool + args hash in `approved_calls`) turns an `ask` into `allow` but never overrides a `block`. Perf: 1,000 rules × 10,000 calls p95 < 20 ms.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (precompile regex/globs in `parse_policy`; evaluate in order, collect matches, apply precedence). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: policy evaluator with default-deny and precedence`.

### Task 9: Budgets and rate limits

**Files:**
- Create: `…/policy/budgets.py`
- Test: `agentshield/tests/unit/test_budgets.py` (fakeredis), `agentshield/tests/integration/test_budget_mirror.py`

**Interfaces:**
- Produces: `class BudgetTracker: async def check(self, agent_id: str, budgets: Budgets) -> BudgetStatus` and `async def record(self, agent_id: str, tokens: int, cost_micro_usd: int) -> None`; `BudgetStatus(ok: bool, exceeded: str | None)`; hourly mirror job writing `budget_counters`.

- [ ] **Step 1: Write failing tests** — cost/calls/tokens limits trip; rpm sliding window; counters reset at UTC midnight; `record` is atomic under concurrency (100 parallel increments); Redis error raises `BudgetUnavailable`.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: per-agent budgets and rate limits`.

### Task 10: Wire M1 into the proxy and `/v1/check`

**Files:**
- Create: `…/gateway/routes_check.py`
- Modify: `…/gateway/routes_anthropic.py`, `…/gateway/routes_openai.py`, `…/gateway/app.py`
- Test: `agentshield/tests/integration/test_policy_proxy.py`, `agentshield/tests/integration/test_check_api.py`

**Interfaces:**
- Consumes: Task 5 `ToolVerdict`, Task 8 `evaluate`, Task 9 `BudgetTracker`, Task 6 `Emitter`.
- Produces: `async def decide_tool_call(ctx, call: ToolCall, session: SessionState, user_request: str) -> CheckResponse` (shared by proxy and check API; emits `tool.requested`, `policy.decision`, and `tool.rewritten`); route `POST /v1/check`; `mode: monitor` returns `allow` with `would_have`.

- [ ] **Step 1: Write failing tests** — proxy: the demo scenario (model stub emits `send_email` to `x@unknown.com`) → client receives the block text, `stop_reason=end_turn`, and an audit trail with `rule_id=deny-external-send`; allowed `read_email` passes untouched; monitor mode logs `would_have=block` but passes; budget exceeded → blocked with `budget.exceeded`; check API: prompt §9 request returns the §9 response shape; unknown tool → `default-deny`; **Redis down** → `send_email` blocked, `read_email` allowed (Review Focus 7); evaluator exception → fail rule; check API rate-limited per key (429).
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: enforce permission policy in proxy and check api`.

### Task 11: Approvals

**Files:**
- Create: `…/policy/approvals.py`
- Modify: `…/gateway/routes_admin.py`, `…/gateway/routes_check.py`
- Test: `agentshield/tests/unit/test_approvals.py`, `agentshield/tests/integration/test_approval_flow.py`

**Interfaces:**
- Produces: `async def request_approval(ctx, session_id, call: ToolCall, trace_id: str) -> Approval`; `async def decide(ctx_user, approval_id, approve: bool) -> Approval`; `async def expire_due(now) -> int`; webhook `POST` with JSON `{approval_id, agent, tool, arguments_redacted, expires_at, dashboard_url}`; routes `GET /v1/approvals/{id}`, `GET /v1/admin/approvals`, `POST /v1/admin/approvals/{id}/approve|deny`; long-poll via `wait_seconds` (≤ 30).

- [ ] **Step 1: Write failing tests** — ask → approval row `pending` + webhook sent (respx) with **redacted raw args, no model prose**; approve → `allow:{session}:{tool}:{args_hash}` set for 900 s and the same call is then allowed; deny/expire → `block`; 300 s timeout (fake clock) → `expired`; **an agent key cannot approve** (403); analyst/admin can, viewer cannot; second decision on a decided approval → 409; webhook failure emits an audit event and does not lose the approval.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: human approval queue with webhook and timeout`.

**Stage 2 gate:** `pytest agentshield/tests -m "stage2"` and a manual run: the stub agent calling `send_email` externally is blocked while `read_email` works.

---

# STAGE 3 — Injection firewall (gate: TPR/FPR measured on a labelled set)

### Task 12: Normalizer

**Files:**
- Create: `…/scan/normalizer.py`
- Test: `agentshield/tests/unit/test_normalizer.py`

**Interfaces:**
- Produces: `@dataclass class Normalized(text: str, hidden_text: str, transforms: list[str], offset_map: list[int], truncated: bool, unscannable: bool)`; `def normalize(raw: str | bytes, *, max_bytes: int = 200_000) -> Normalized`; `offset_map` lets a span in `text` be mapped back to the original string.

- [ ] **Step 1: Write failing tests** — zero-width/bidi stripped (`transforms` lists them); NFKC folds full-width letters; HTML comments and `display:none`/`font-size:0`/white-on-white text go to `hidden_text`; base64 blob ≥ 24 chars decoded (depth ≤ 2) and appended with a marker; mixed-script homoglyph word flagged; **empty string, non-UTF-8 bytes, and 5 MB input** return a `Normalized` (`unscannable`/`truncated`), never raise (Review Focus 3); span mapping round-trips on a text with removed characters.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: content normalizer for hidden and encoded text`.

### Task 13: Rule engine and signatures

**Files:**
- Create: `…/scan/rules.py`, `…/scan/rules.yaml`
- Test: `agentshield/tests/unit/test_rules.py`

**Interfaces:**
- Produces: `@dataclass(frozen=True) class RuleHit(rule_id: str, category: str, weight: float, span: tuple[int,int], text: str)`; `def load_rules(path: Path) -> list[Rule]`; `def run_rules(norm: Normalized, rules: Sequence[Rule]) -> list[RuleHit]`; `def rule_score(hits: Sequence[RuleHit]) -> float` (max weight, +0.1 per additional distinct category, cap 1.0).

- [ ] **Step 1: Write failing tests** — at least 12 attack phrases hit (ignore previous instructions, forward all to address, reveal system prompt, "you are now", send contents to URL, etc.) with correct spans; **hard negatives** ("Security training: attackers write 'ignore previous instructions'" in quotes, a normal "please forward this to finance") score below 0.35 (Review Focus 4); hits in `hidden_text` are reported with `hidden=True`; every rule in `rules.yaml` has an id, category, weight and at least one positive and one negative fixture (enforced by a test that iterates the file).
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: injection signature rules with spans`.

### Task 14: Classifier service

**Files:**
- Create: `…/scan/classifier.py`, `scripts/export_classifier_onnx.py`
- Test: `agentshield/tests/unit/test_classifier.py`, `agentshield/tests/perf/test_classifier_latency.py` (marked `slow`)

**Interfaces:**
- Produces: `class Classifier(Protocol): def score(self, text: str) -> float`; `class OnnxClassifier(model_dir: Path)` (tokenizer + onnxruntime, max 512 tokens, windows long text and takes the max); `class StubClassifier(keyword_scores: dict[str, float])`; `def load_classifier(settings) -> Classifier` falling back to `NullClassifier` (returns 0.0) **and setting a `degraded` flag** that `/readyz` reports.

- [ ] **Step 1: Write failing tests** — Stub is deterministic; `OnnxClassifier` returns floats in [0,1] on a tiny fixture model checked into `tests/fixtures/`; long text is windowed; missing model dir → degraded flag set + `error` event emitted, never silently "clean"; perf (slow): p95 for ≤ 2 KB input recorded and compared to the spec's 120 ms [unmeasured target] — **the test prints the measured value and fails only if > 250 ms**.
- [ ] **Step 2: Choose the model** — shortlist 2–3 open prompt-injection classifiers, record licence, size and CPU latency in `docs/superpowers/specs/classifier-selection.md`, and pick the smallest permissive-licence one that meets the budget (Open Question 1).
- [ ] **Step 3–4:** implement → pass. **Step 5: Commit** `feat: onnx prompt-injection classifier behind an interface`.

### Task 15: Judge, pipeline, session risk and action check

**Files:**
- Create: `…/scan/judge.py`, `…/scan/pipeline.py`, `…/scan/risk.py`, `…/scan/action_check.py`; `…/gateway/routes_check.py` (add `POST /v1/scan`)
- Modify: `…/gateway/routes_anthropic.py`, `…/gateway/routes_openai.py` (scan `tool_result` blocks, wrap in `<untrusted>`)
- Test: `agentshield/tests/unit/test_pipeline.py`, `test_risk.py`, `test_action_check.py`, `agentshield/tests/integration/test_scan_api.py`

**Interfaces:**
- Produces: `async def scan(content: Content, ctx: ScanContext) -> ScanResult` (`verdict: clean|suspicious|malicious`, `confidence`, `layers`, `findings`, `sanitized_text`, `risk_score`); `def update_risk(current: float, verdict: str, confidence: float) -> float` implementing `1-(1-r)*(1-0.6*c)`; `async def judge(text, upstream, timeout=1.5) -> JudgeVerdict`; `def action_in_scope(user_request: str, call: ToolCall, allowed_domains: set[str]) -> ActionCheck`; session risk stored in Redis `risk:{session}` and in `sessions.risk_score`.

- [ ] **Step 1: Write failing tests** — score < 0.35 → clean, no judge call; 0.35–0.80 → judge called exactly once; ≥ 0.80 → malicious, **no judge call**; judge timeout → `suspicious`/0.5 and the content passes (Review Focus 3); `on_malicious=sanitize` replaces the span with `[removed by AgentShield]`, falls back to `quarantine` when no span; repeated suspicious scans raise session risk monotonically; **judge prompt contains the content only inside delimiters and the judge call has no tools**; action check flags `send_email` to an address absent from the user request and allow-list; `/v1/scan` on empty/5 MB input → 200 with a verdict; scanned `tool_result` is wrapped in `<untrusted source=… id=…>`; the email demo path raises risk above the `tighten-on-risk` threshold.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: layered injection pipeline with session risk`.

### Task 16: Eval harness and datasets

**Files:**
- Create: `eval/run_eval.py`, `eval/datasets/{attacks,clean}.jsonl`, `eval/README.md`, `eval/datasets/SOURCES.md`
- Test: `agentshield/tests/unit/test_eval_runner.py`

**Interfaces:**
- Produces: `python eval/run_eval.py --stack rules|rules+classifier|full --split dev|test --out eval/results/<ts>.json`; output JSON `{dataset: {n_attack, n_clean, split}, thresholds, tpr, fpr, per_category_recall, latency_ms: {layer: {p50,p95}}}`.

- [ ] **Step 1: Write failing tests** — runner on a 6-sample fixture dataset computes TPR/FPR exactly; split is deterministic (hash of id); the report refuses to print "detection rate" without also printing FPR.
- [ ] **Step 2: Build datasets** — ~60 hand-written email/web/PDF-style attacks across direct, indirect, zero-width, base64, HTML-comment, homoglyph and multilingual categories; ≥ 200 clean items incl. hard negatives; any public sample must have its licence recorded in `SOURCES.md`; 70/30 dev/test split.
- [ ] **Step 3: Run** all three stacks on `dev`, tune thresholds in `scan/pipeline.py` constants, **then run once on `test`**; write the measured numbers and dataset composition into `eval/README.md`.
- [ ] **Step 4: Commit** `feat: injection eval harness with measured detection and false-alarm rates`.

**Stage 3 gate:** `eval/README.md` contains measured TPR **and** FPR on the held-out split with the full stack.

---

# STAGE 4 — Replay and dashboard (gate: one attack replayed end to end)

### Task 17: Timeline, search, replay and policy simulator API

**Files:**
- Create: `…/audit/{search,replay}.py`; `…/gateway/routes_admin.py` (add routes)
- Test: `agentshield/tests/unit/test_replay.py`, `agentshield/tests/integration/test_replay_api.py`, `agentshield/tests/security/test_tenant_isolation.py` (extend)

**Interfaces:**
- Produces: `GET /v1/admin/events?agent=&session=&tool=&decision=&from=&to=&cursor=`; `GET /v1/admin/sessions/{id}/timeline`; `async def replay_session(ctx, session_id, *, policy_version: int | None) -> ReplayResult(steps: list[ReplayStep], changed: list[StepDiff])` (re-evaluates recorded `tool.requested` events with `evaluate`; recorded model text is shown, never re-run); `POST /v1/admin/policies/{agent}/simulate {version, session_ids|since}`; incidents `POST /v1/admin/incidents`; `GET /v1/admin/sessions/{id}/export.json`.

- [ ] **Step 1: Write failing tests** — timeline returns events in `seq` order and groups by `trace_id`; replay with the active version reproduces recorded decisions exactly; replay against a new version reports `changed` for a deliberately relaxed rule; **viewer role gets redacted payloads only**, analyst can mark incidents; every route returns 404 for another tenant's session/trace ids (extends Task 3's parametrized test); export JSON contains the chain head hash.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat: timeline, replay and policy simulation`.

### Task 18: Dashboard

**Files:**
- Create: `dashboard/` (Vite + React + TS): pages `Login`, `Agents`, `AgentDetail` (create key + copy-paste endpoint snippet), `Policies` (editor, validate, simulate, activate), `Approvals`, `Sessions` (timeline + replay), `Alerts`
- Test: `dashboard/src/**/*.test.tsx` (Vitest + Testing Library), `dashboard/e2e/attack_replay.spec.ts` (Playwright)

**Interfaces:**
- Consumes: the admin/audit API from Tasks 3, 7, 11, 17.
- Produces: static build served by nginx; typed API client `dashboard/src/api.ts`.

- [ ] **Step 1: Write failing tests** — component tests: approvals list shows **raw tool + redacted args** and not model prose; policy editor shows server-side validation errors with line numbers; replay page renders each step with decision badge and rule id; the key is shown once and masked after reload. E2E (Playwright against compose): log in → create agent → copy endpoint → run the attack through the proxy → alert appears → open timeline → replay shows the block.
- [ ] **Step 2–4:** fail → implement → pass (E2E last). **Step 5: Commit** `feat: dashboard for agents, policies, approvals and replay`.

### Task 19: SDK, email-agent demo, Compose and quickstart

**Files:**
- Create: `sdk/python/agentshield_sdk/{client,guard}.py`, `demo/email_agent/{agent,tools,mailbox}.py`, `demo/email_agent/run_unprotected.py`, `demo/email_agent/run_protected.py`, `deploy/docker-compose.yml`, `README.md`
- Test: `sdk/python/tests/test_guard.py`, `demo/email_agent/tests/test_demo_end_to_end.py`

**Interfaces:**
- Produces: `class AgentShield(base_url: str, api_key: str)` with `check(tool, arguments, *, session_id, user_request, untrusted_inputs=()) -> CheckResponse` and `scan(...)`; `@guard(tool_tag: Literal["read","write","external","financial"])` decorator that calls `check` and implements the fail rule when the gateway is unreachable; `seed-demo` CLI creating tenant, agent, policy (spec §2.1 sample), stub upstream.

- [ ] **Step 1: Write failing tests** — SDK: gateway down + `external` tool → raises `Blocked`; gateway down + `read` tool → runs and logs locally; `ask` decision polls the approval until decided or timeout → denied. Demo: `run_unprotected` sends the mail to the attacker address (mock outbox); `run_protected` does not, and the audit log for the trace contains `content.scanned(malicious)`, `policy.decision(block, deny-external-send)`; the only difference between the two scripts is the base URL env var.
- [ ] **Step 2–4:** fail → implement → pass; `docker compose up` brings up the full stack and `scripts/demo.sh` completes.
- [ ] **Step 5: README + GIF** — quickstart (`docker compose up`, create agent, change one base URL), the measured numbers copied from `eval/README.md`, and an explicit "what it does not catch" section. **Commit** `feat: sdk, email-agent demo and compose stack`.

**Stage 4 gate:** the Playwright test `attack_replay.spec.ts` passes against the compose stack; `verify-chain` passes; the demo script from spec §6.4 runs start to finish.

---

## Self-Review (run when writing, results recorded)

- **Spec coverage:** M1 → tasks 7–11; M2 → 12–16; M5 → 6, 17, 18; gateway/proxy → 3–5, 10; SDK/demo → 19; stored+passthrough keys → 3–4; multi-tenancy → 2–3, 17; approvals (dashboard + webhook, 5-min timeout) → 11, 18; block-as-rewritten-reply → 5, 10; fail rule → 5, 10, 19; reporting both TPR and FPR → 16. **M3/M4:** tables and event types exist (task 2); no tasks by design (spec §2.3–2.4).
- **Type consistency:** `ToolCall`, `ToolVerdict`, `Decision`, `PolicyDoc`, `SessionState`, `Evaluation`, `TenantContext`, `Emitter`, `Normalized`, `RuleHit` are defined once and referenced by those names.
- **Proportion:** tasks give signatures, test names/assertions and exact values; bodies are left to the implementer except the risk formula and rewrite rules, which the spec fixes.
