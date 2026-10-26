# AgentShield SDK, Demo and Eval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure the injection firewall honestly, ship a Python SDK for check-mode agents, and build the email-agent attack demo, the Compose stack, the README and (optionally) a hosted read-only replay.

**Architecture:** `eval/` runs the backend's `scan()` pipeline directly on labelled datasets. `sdk/python` is a small client over `/v1/check`, `/v1/scan`, `/v1/approvals`. `demo/email_agent` is a LangGraph agent whose only difference between unprotected and protected runs is its model base URL.

**Tech Stack:** Python 3.12, httpx, pydantic v2, LangGraph + langchain-openai (demo), pytest, Docker Compose, vhs (terminal GIF) or Playwright video for the dashboard GIF.

**Spec:** `docs/superpowers/specs/2026-10-26-agentshield-design.md` §6 (test plan, demo script), §7.4 (decisions); `…-backend-api-db.md` §A.4 (check/scan shapes).

## Global Constraints
- The eval always reports TPR **and** FPR together with dataset composition, split and thresholds; the README only copies numbers a run printed (arch §2.2, §6.2).
- Targets TPR ≥ 0.90, FPR ≤ 0.03 are reported, not gates (arch §7.2a).
- Public samples are used only with their licence recorded in `eval/datasets/SOURCES.md`.
- The SDK implements the fail rule exactly: only `read` tools fail open when AgentShield is unreachable (arch §8.6).
- The demo's protected and unprotected runs differ only in connection settings — `OPENAI_BASE_URL` and `OPENAI_API_KEY` — never in code (arch §6.4); the CI demo uses the stub upstream, a real LLM only with `DEMO_UPSTREAM=real`.
- No real provider keys in the repo.

## Review Focus
1. **Eval leakage:** a sample used to tune thresholds must never appear in the test split (deterministic split by id hash, test asserts disjointness) → E1.
2. **Near-duplicate samples** inflating scores (same attack with one word changed) are grouped so all variants land in the same split → E1.
3. **SDK clock and network edge cases:** timeouts, DNS failure, 5xx from AgentShield, and an `ask` that is never decided all resolve to the fail rule or a deny, never to silently running the tool → E2.
4. **Demo idempotency:** running the demo twice in a row gives the same outcome (fresh session id per run, mailbox reset) → E3.

---

### Task E1: Eval harness and datasets (closes stage 3)

**Files:** Create `eval/run_eval.py`, `eval/datasets/{attacks,clean}.jsonl`, `eval/datasets/SOURCES.md`, `eval/README.md`, `eval/results/.gitkeep`; Test `eval/tests/test_run_eval.py`

**Interfaces:**
- Consumes: `agentshield.scan.pipeline.scan` (B15) with a stack switch `rules | rules+classifier | full`, classifier preset switch `protectai_v2 | prompt_guard_2_22m`.
- Produces: CLI `python eval/run_eval.py --stack full --classifier protectai_v2 --split test --out eval/results/<ts>.json`; JSON `{dataset: {n_attack, n_clean, split, sha256}, thresholds, tpr, fpr, per_category_recall, latency_ms: {layer: {p50, p95}}}`; a Markdown table appended to `eval/README.md` by `--write-readme`.

- [ ] **Step 1: Write failing tests** — exact TPR/FPR on a 6-sample fixture; split is deterministic and **train/test disjoint** (Review Focus 1); samples sharing `group_id` land in one split (Review Focus 2); the report function refuses to render a detection rate without FPR; dataset rows validate against the schema `{id, group_id, text, label: attack|clean, category, source, licence}`.
- [ ] **Step 2: Build datasets** — attacks: ≥ 60 hand-written across `direct`, `indirect-email`, `indirect-web`, `indirect-pdf-text`, `zero-width`, `base64`, `html-comment`, `css-hidden`, `homoglyph`, `multilingual`, `exfil-url`, `tool-description`; clean: ≥ 200 including ≥ 40 **hard negatives** (security-training text quoting attacks, legitimate "forward this to finance", newsletters with "ignore this email if…"); optional public samples with licences recorded. You (the user) review a random 20 % sample of the hand-written items before the test split is run.
- [ ] **Step 3: Run** all stacks × both classifier presets on `dev`, tune thresholds in `scan/pipeline.py` constants, then run **once** on `test`; write results and composition into `eval/README.md`.
- [ ] **Step 4: Commit** `feat(eval): labelled injection set and honest tpr/fpr report`.

**Stage 3 gate:** `eval/README.md` shows TPR and FPR on the held-out split for all three stacks.

### Task E2: Python SDK

**Files:** Create `sdk/python/pyproject.toml`, `sdk/python/agentshield_sdk/{__init__,client,guard,errors}.py`; Test `sdk/python/tests/{test_client,test_guard}.py`

**Interfaces:**
- Consumes: `openapi.json` (B16) for request/response models (generated with `datamodel-code-generator` into `agentshield_sdk/_models.py`).
- Produces: `AgentShield(base_url: str, api_key: str, *, timeout: float = 2.0)`; `.check(tool, arguments, *, session_id, user_request, untrusted_inputs=(), effect_tag=None, wait_seconds=0) -> CheckResponse`; `.scan(text, *, source, id, session_id) -> ScanResult`; `.wait_for_approval(approval_id, timeout_s=300) -> Decision`; decorator `@shield.guard(tool_name: str, effect_tag: EffectTag)` that checks before running the wrapped tool and raises `Blocked(reason, rule_id, trace_id)`.
- [ ] **Step 1: Failing tests** (respx) — allow runs the tool; block raises `Blocked` with rule id; ask → polls until approved (runs) / denied or timeout (raises); **gateway unreachable / timeout / 5xx**: `read` tool runs and logs a warning, every other tag raises `Blocked(rule_id="agentshield-unreachable")` (Review Focus 3); API key never appears in exception messages or logs.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(sdk): python sdk with guard decorator and fail rule`.

### Task E3: Email-agent demo and Compose stack

**Files:** Create `demo/email_agent/{agent,tools,mailbox,run_unprotected,run_protected}.py`, `demo/email_agent/mailbox/*.eml` (one poisoned with hidden HTML + zero-width instruction), `deploy/docker-compose.yml`, `deploy/.env.example`, `Makefile` (`make up`, `make demo`, `make down`); Test `demo/email_agent/tests/test_demo_end_to_end.py`

**Interfaces:**
- Consumes: `agentshield seed-demo` (B17), stub upstream (B4) scripted to follow the injected instruction, gateway proxy (B4–B15).
- Produces: `run_unprotected.py` / `run_protected.py` printing a short transcript and the mock outbox; Compose services `postgres:18`, `redis:7`, `gateway`, `worker`, `dashboard` (nginx), `stub-upstream`; `make demo` = up → seed → unprotected → protected → print dashboard URL for the session.
- [ ] **Step 1: Failing tests** — unprotected run: mock outbox contains a mail to `x@unknown.com`; protected run: outbox empty, agent's final reply contains "Action blocked by AgentShield", audit trail for the trace has `content.scanned` (malicious), `policy.decision` (`block`, `deny-external-send` or `tighten-on-risk`), and the chain verifies; the two scripts differ only in env (test diffs the resolved config); running `make demo` twice gives the same result (Review Focus 4).
- [ ] **Step 2–4:** fail → implement → pass; `docker compose up` healthy within 60 s on the reference machine.
- [ ] **Step 5: Commit** `feat(demo): email-agent attack demo and compose stack`.

### Task E4: README, quickstart, GIF (closes stage 4 with F6)

**Files:** Create/modify `README.md`, `docs/demo.gif`, `docs/architecture.svg` (from arch §3), `CONTRIBUTING.md`, `SECURITY.md`
- [ ] **Step 1:** README sections: what it is (one paragraph), 3-minute quickstart (`make up`, connect an agent by changing one base URL — snippets for OpenAI SDK, Anthropic SDK, Claude Code), how decisions work (policy sample from arch §2.1), **measured results** copied from `eval/README.md` with dataset size, **what it does not catch** (no classifier is complete; tool-allowed exfiltration; non-English coverage of the 22M model; MCP proxy not yet), architecture figure, licence Apache-2.0.
- [ ] **Step 2:** Record `docs/demo.gif` (terminal run + dashboard tape) ≤ 8 MB.
- [ ] **Step 3:** `SECURITY.md` with a disclosure address and the platform's own threat model summary (arch §1.4).
- [ ] **Step 4: Verify** every number in README appears in the latest `eval/results/*.json` (a small script `scripts/check_readme_numbers.py` run in CI).
- [ ] **Step 5: Commit** `docs: readme, quickstart, demo gif and security policy`.

### Task E5 (optional, stage 4b): Hosted read-only replay
**Files:** Create `dashboard/src/features/sessions/StaticReplay.tsx` (reads a bundled export JSON), `deploy/static-replay/` build config.
- [ ] **Step 1: Failing tests** — static build makes **no network calls** except its own assets (Playwright request interception), shows the recorded attack tape, and labels itself "Recorded demo — no live agent".
- [ ] **Step 2–4:** fail → implement → pass; publish to a free static host.
- [ ] **Step 5: Commit** `feat(demo): hosted read-only replay`.

## Self-Review
- **Spec coverage:** arch §6.2 → E1; §6.4 demo script → E3 (+F6 E2E); §7.4(1) both classifier presets evaluated → E1; §7.4(2) Compose + GIF + optional hosted replay → E3, E4, E5; §8.6 fail rule in SDK → E2; prompt success criterion "public demo" → E4/E5.
- **Type consistency:** SDK types generated from `openapi.json`; `EffectTag`, `Decision`, `CheckResponse` match B1.
- **Review Focus:** all four items have named tests.
