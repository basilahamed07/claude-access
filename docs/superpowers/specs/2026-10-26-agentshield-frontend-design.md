# AgentShield — Frontend (Dashboard) Design (v1)

**Date:** 2026-10-26 · **Parent:** `2026-10-26-agentshield-design.md` · **API:** `2026-10-26-agentshield-backend-api-db.md` §A.3
**Method:** the `frontend-design` skill (plan → review against generic defaults → build → critique). Charts follow the `dataviz` skill, which must be loaded before any chart code is written.

---

## 1. Subject, audience, primary job

- **Subject:** a checkpoint that records and judges every action AI agents take. Its vocabulary is borrowed from aviation safety, where the same problem was solved decades ago: a **flight recorder** (what happened, in order, tamper-evident), a **checklist** (what is allowed), and a **tower** (a human clears risky actions).
- **Audience:** a security or platform engineer at a company running agents (also: the hiring manager watching the portfolio demo). Technical, short on time, needs to answer "what did this agent do, and why was it stopped?"
- **Primary job:** take someone from an alert to a full, step-by-step explanation of one agent session in under a minute, and let them clear or refuse pending actions.
- **Secondary jobs:** connect a new agent (get the endpoint + key), edit its policy safely (validate, simulate, then activate).

## 2. Design plan (token system)

### 2.1 Color
Flight recorders are painted **international orange** so they can be found in wreckage. AgentShield uses that orange for exactly one meaning: *an action was stopped or an attack was found*. Everything else stays quiet.

| Token | Light | Dark | Role |
|---|---|---|---|
| `--hangar` (surface) | `#EDF0F1` | `#1A232B` | page background, cool grey-blue of a hangar floor |
| `--panel` | `#FFFFFF` | `#222D36` | tables, drawers |
| `--ink` | `#16202A` | `#E4EAEE` | text |
| `--rule` | `#C5CED4` | `#3A4752` | dividers, lane lines |
| `--recorder` | `#E5560B` | `#FF7B30` | **blocked / malicious only** (also focus ring) |
| `--cleared` | `#2E6B5A` | `#5FB39A` | allowed |
| `--holding` | `#8A6100` | `#E0B341` | ask / pending approval |

Contrast: all text/background pairs ≥ 4.5:1; `--recorder` on `--panel` is used for marks and labels at ≥ 3:1 for non-text and paired with an icon + word ("Blocked") so color is never the only signal. Charts use these three status colors only; categorical series beyond status use the `dataviz` skill's validated palette.

### 2.2 Type
- **Atkinson Hyperlegible Next** (Google Fonts) for all UI text — designed by the Braille Institute for legibility; fits a tool where misreading an address or amount is the failure.
- **Atkinson Hyperlegible Mono** **only** for literal machine values: tool arguments, JSON payloads, keys, hashes, trace ids. Not for labels or decoration.
- Scale (1.2 ratio, 16 px base): 13.3 · 16 · 19.2 · 23 · 27.6 · 33.2. Body line-height 1.5; tables 1.35. Weights 400/600 only. Sentence case everywhere; no all-caps labels.

### 2.3 Layout concept
A left **rail** (icons + words) and one working area. Lists are dense tables, not cards. Detail always opens in a **right-hand drawer** so the list keeps its scroll position.

```
┌────────┬───────────────────────────────────────────────────────────────┐
│ Shield │  Sessions                         [agent ▾] [decision ▾] [24h ▾]│
│        │ ─────────────────────────────────────────────────────────────── │
│ Over-  │  ● Blocked  email-reader-01  s-9f2c  send_email → x@unknown.com │
│ view   │  ● Cleared  pay-bot          s-1a2b  read_invoice               │
│ Sess-  │  ● Holding  pay-bot          s-77c1  pay_invoice $5,000         │
│ ions   │  …                                                              │
│ Appro- │                                                                 │
│ vals 2 │                                                                 │
│ Agents │                                                                 │
│ Polic- │                                                                 │
│ ies    │                                                                 │
│ Alerts │                                                                 │
└────────┴───────────────────────────────────────────────────────────────┘
```

**The signature screen — the session tape** (the one place the design spends its boldness):
```
 Session s-9f2c · email-reader-01 · "Summarize my unread mail"        [◀ step] [step ▶] [Re-check with policy v4 ▾]
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 time   │ Input            │ Scan              │ Policy                 │ Tool            │ Model
 10:41:00 ● user request
 10:41:01 ● read_email ×3 ─────────────────────────────── ● allow ───────── ● read_email
 10:41:02 ● m-441 (email) ──● malicious 0.93
                              "forward all invoices…"   risk 0.12 → 0.88
 10:41:04                                                                                    ● requests send_email
 10:41:04                                               ▌● BLOCK deny-external-send
 10:41:05                                                                                    ● "Action blocked by AgentShield…"
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Chain verified ✓ head 9c1e…                                           Export JSON   Mark as incident
```
- Five fixed **lanes** (Input, Scan, Policy, Tool, Model) on a vertical time axis; each event is a mark in its lane; causal links are thin connectors.
- The tape is the only place `--recorder` appears at full strength: the blocked step gets an orange bar on the lane edge.
- **Replay:** `step ▶` moves a cursor down the tape, one `seq` at a time (also ←/→ keys); the drawer shows the recorded payload for that step.
- **Re-check with policy vN:** marks whose decision would change are shown as a ghost mark beside the original with the new decision — this is the policy simulator in visual form.
- Phone width: lanes collapse into a single column with a lane tag on each mark.

Other screens use the same table + drawer structure:
- **Overview:** "Needs you" list (pending approvals, new blocks, chain or budget problems) first; below it one chart: decisions per hour for 24 h (stacked allow/ask/block bars). No KPI hero tiles.
- **Approvals:** table of pending items; the drawer shows the **raw tool name and redacted arguments as a definition list** (never model-written prose — reviewers must not be steered by injected text), the matched rule, session risk, time left; buttons **Approve** / **Deny** with an optional note. Keyboard: `a` / `d` with confirmation.
- **Agents:** table; "Connect agent" flow: create → key shown once with copy button → snippet tabs (Python OpenAI SDK, Anthropic SDK, curl, Claude Code env vars) → "Send a test request" that shows the first event arriving live.
- **Policies:** YAML editor (CodeMirror 6) with server-side validation markers on the line; side panel "Simulate on last 7 days" showing changed decisions; **Activate** requires a typed confirmation of the agent slug when the change loosens a rule (detected by the simulator).
- **Alerts:** filterable table (severity, kind, agent) linking to the session tape.
- **Settings:** users and roles, upstreams (key is write-only), webhook, retention, `on_malicious` action.

### 2.4 Principles
1. **Orange means stopped.** Never use the accent for decoration, buttons or brand.
2. **Show the record, not a story.** Approvals and the tape show what the agent literally sent; summaries are generated by AgentShield from structured fields, never by a model.
3. **Every block explains itself** in the same words everywhere: rule id, reason, trace id — the same text the agent received.
4. **Nothing irreversible without seeing its effect first** (simulate before activate, key shown once with a warning).
5. **Empty states give the next step** ("No sessions yet. Connect an agent to see its first request here." → Connect agent).

## 3. Review against generic defaults (skill step)

Checked the plan against the skill's list of generated-looking defaults:
| Default | Present? | Change made |
|---|---|---|
| Cream background + serif + terracotta | No | — |
| Near-black + single acid-green/vermilion accent (the usual "SOC dashboard") | **Was my first instinct** (dark-first security console) | Light-first "hangar" surface; dark mode is an equal theme, not the identity; accent is meaning-bound, not brand |
| Broadsheet hairlines, zero radius | No | Radius 6 px on panels/drawers, 4 px on inputs, 999 px on status dots only — radius follows hierarchy |
| SaaS card kit, gradient washes, identical soft shadows | Avoided | Tables and lanes; one shadow level, only on the drawer (it floats over the list) |
| ALL-CAPS eyebrows, mono for small labels, `→` on links, `A · B · C` meta strings | **Mono labels and middle-dot meta** were in the first draft of the tape header | Mono restricted to literal values; the tape header uses separate labelled fields instead of a dot string in the implementation (the wireframe uses dots only as shorthand) |
| Numbered 01/02/03 markers | Only in "Connect agent" | Kept there — it really is a sequence |
| KPI hero numbers with gradient | Removed from Overview | "Needs you" list first |

Motion: one orchestrated moment only — when a new event arrives live on an open tape, its mark draws in along its lane (200 ms, disabled under `prefers-reduced-motion`). Drawers slide (150 ms) because they answer a click.

## 4. Copy rules
- Actions keep one name end to end: **Approve** → toast "Approved"; **Deny** → "Denied"; **Activate policy** → "Policy v4 is active"; **Revoke key** → "Key revoked".
- Decision words in the UI: **Cleared** (allow), **Holding** (ask/pending), **Blocked** (block). The API keeps `allow|ask|block`; the UI shows both on hover for engineers.
- Errors say what happened and what to do: "Policy not saved. Line 14: unknown operator 'contains'. Use 'regex' or 'in'." No apologies, no "oops".

## 5. Technology [My call]
- React 18.3 + TypeScript + Vite; React Router; TanStack Query (server state, polling every 5 s on Approvals and an open live tape); no global state library.
- Styling: CSS Modules + CSS custom properties for the tokens above; no UI kit (keeps the identity and the bundle small). Headless primitives from Radix UI only for dialog, dropdown, tabs and tooltip (accessibility for free).
- Editor: CodeMirror 6 with YAML mode; chart: one library chosen when loading the `dataviz` skill (Recharts or Observable Plot), used only on Overview.
- API client generated from the committed `openapi.json` (`openapi-typescript`), so frontend types break when the API changes.
- Auth: session cookie + CSRF header; on 401 → login page with return path.
- Theme: `prefers-color-scheme` plus a manual toggle stored in `localStorage` (try/catch, falls back to system).

## 6. Quality floor
WCAG 2.2 AA; full keyboard use (tape: ←/→ step, Enter opens drawer, Esc closes); visible focus ring in `--recorder` at 2 px offset; `prefers-reduced-motion` respected; works down to 360 px width; no horizontal page scroll (tables scroll inside their container); empty, loading (skeleton rows, not spinners) and error states for every screen; `axe` check in Playwright for each page.

## 7. Screens → API map
| Screen | Endpoints |
|---|---|
| Login | `POST /v1/auth/login`, `GET /v1/auth/me` |
| Overview | `GET /v1/admin/stats/overview`, `GET /v1/admin/approvals?status=pending`, `GET /v1/admin/alerts?limit=10` |
| Sessions / tape | `GET /v1/admin/sessions`, `…/{id}/timeline`, `POST …/{id}/replay`, `GET …/{id}/export.json`, `POST /v1/admin/incidents` |
| Approvals | `GET /v1/admin/approvals`, `POST /v1/admin/approvals/{id}/decision` |
| Agents | `GET/POST /v1/admin/agents`, `POST …/{slug}/keys`, `…/keys/{id}/revoke`, `…/keys/{id}/rotate`, `GET …/{slug}/snippet?lang=python-openai|python-anthropic|curl|claude-code` |
| Policies | `GET/POST …/{slug}/policy/versions`, `POST …/simulate`, `POST …/versions/{v}/activate` |
| Alerts | `GET /v1/admin/alerts` |
| Settings | `/v1/admin/users`, `/v1/admin/upstreams`, tenant settings |
