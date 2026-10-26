# AgentShield v1 — Plan Overview (index)

> **For agentic workers:** this file is the index. Execute the sub-plans below task by task with superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Each sub-plan carries its own header, Global Constraints and Review Focus; the constraints in this file apply to all of them.

**Goal:** Build AgentShield stages 1–4 (gateway + audit, permission control, injection firewall, replay + dashboard) with SDK, eval and the email-agent demo.

**Specs (read before any task):**
- Architecture: `docs/superpowers/specs/2026-10-26-agentshield-design.md`
- Backend API + DB: `docs/superpowers/specs/2026-10-26-agentshield-backend-api-db.md`
- Frontend: `docs/superpowers/specs/2026-10-26-agentshield-frontend-design.md`

## Sub-plans

| File | Scope | Tasks |
|---|---|---|
| `2026-10-26-agentshield-01-backend.md` | Python service: contracts, DB, auth, proxy, audit, M1, M2, replay API, API hardening | B1–B17 |
| `2026-10-26-agentshield-02-frontend.md` | React dashboard | F1–F6 |
| `2026-10-26-agentshield-03-sdk-demo-eval.md` | Eval harness + datasets, Python SDK, email-agent demo, Compose, README, optional hosted replay | E1–E5 |

## Execution order and stage gates

A stage starts only when the previous gate passes (architecture spec §5).

| Stage | Tasks (in order) | Gate (how it is checked) |
|---|---|---|
| 1 Core gateway + audit | B1 → B2 → B3 → B4 → B5 → B6 | A request through `/v1/messages` and `/v1/chat/completions` (stream and non-stream) produces events visible via `GET /v1/admin/events?trace=…` (added early in B6 as a minimal read route) and `agentshield verify-chain` passes |
| 2 Permission control | B7 → B8 → B9 → B10 → B11 | Integration test `test_stage2_gate_forbidden_tool_blocked`: stub agent's `send_email` to an external domain is rewritten to a block; `read_email` passes |
| 3 Injection firewall | B12 → B13 → B14 → B15 → E1 | `eval/README.md` contains TPR **and** FPR measured on the held-out split for all three stacks |
| 4 Replay + dashboard | B17 → B16 → F1 → F2 → F3 → F4 → F5 → E2 → E3 → F6 → E4 | Playwright `attack_replay.spec.ts` passes against `docker compose up`; demo script (spec §6.4) runs end to end |
| 4b optional | E5 | Static hosted replay loads the recorded session |

B16 runs **after** B17 so the committed `openapi.json` already contains every stage-4 route; F1–F5 start once B16 is merged (they consume the generated client). Any later API change regenerates `openapi.json` in the same commit (the snapshot test enforces it).

## Cross-plan interfaces (names every plan uses)

| Name | Defined in | Used by |
|---|---|---|
| `agentshield/openapi.json` (committed) | B16 | F1 (generated TS client), E2 (SDK types) |
| `Decision` = `allow \| block \| ask`; UI words Cleared / Holding / Blocked | B1 | all |
| `CheckRequest` / `CheckResponse` (prompt §9 shape + `approval_id`, `mode`, `would_have`) | B1 | B10, E2, E3 |
| Effect tags `read, write, destructive, external, financial, execute` | B7 | B10, E2, F3 |
| Audit event envelope `agentshield.event/1` and the canonical event-type list (arch §4.2) | B1, B6 | B17, F5 |
| `agentshield seed-demo` CLI (tenant `acme`, agent `email-reader-01`, policy, stub upstream) | B17 | E3, F6, E4 |
| Stub upstream `agentshield.testing.stub_upstream` (scripted tool calls, both API formats) | B4 | B5, B10, E3 |

## Global constraints (all plans)

- Licence Apache-2.0; every new source file needs no header (the root `LICENSE` covers it).
- Python 3.12, `ruff` + `mypy --strict` clean; TypeScript `strict`, `eslint` clean.
- TDD: each task starts with failing tests named in the plan; commit at the end of each task with a conventional-commit message.
- Branch `claude/elegant-maxwell-ipbatc`; push after each stage gate; no PR unless asked.
- Never put real provider keys in tests, fixtures or docs; tests use the stub upstream.
- Numbers in README/eval may only be ones a run printed.

## Definition of done for v1
All four stage gates pass in CI (GitHub Actions: lint, types, unit, integration with Postgres 18 + Redis 7 service containers, Schemathesis, Playwright), the demo GIF is recorded, and the README states measured TPR/FPR and what AgentShield does not catch.
