# AgentShield Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Before writing any UI code, load the `frontend-design` skill; before writing chart code (F6 Overview), load the `dataviz` skill.

**Goal:** Build the AgentShield dashboard: connect agents, manage policies safely, clear or refuse pending actions, and explain any session through the step-by-step "session tape".

**Architecture:** A React + TypeScript single-page app built by Vite and served as static files by nginx in Compose. It talks only to the control-plane API using a session cookie + CSRF header; types are generated from the committed `agentshield/openapi.json`.

**Tech Stack:** React 18.3, TypeScript 5 (strict), Vite, React Router, TanStack Query, CSS Modules + CSS custom properties, Radix UI primitives (dialog, dropdown, tabs, tooltip), CodeMirror 6 (YAML), openapi-typescript, Vitest + Testing Library, Playwright + @axe-core/playwright.

**Spec:** `docs/superpowers/specs/2026-10-26-agentshield-frontend-design.md` ("fe §n"); endpoints from `docs/superpowers/specs/2026-10-26-agentshield-backend-api-db.md` §A.3.

## Global Constraints

- Tokens exactly as fe §2.1 (light + dark hex values); `--recorder` used **only** for blocked/malicious state and the focus ring (fe §2.4.1).
- Fonts: Atkinson Hyperlegible Next (UI) and Atkinson Hyperlegible Mono (literal values only); type scale 13.3/16/19.2/23/27.6/33.2 px; weights 400/600; sentence case, no all-caps labels (fe §2.2).
- Decision words: Cleared / Holding / Blocked, each with icon + word, never color alone (fe §4).
- Approvals and the tape show raw tool names and redacted arguments, never model-written prose (fe §2.4.2).
- Action names stay identical from button to toast (fe §4).
- WCAG 2.2 AA, keyboard complete, `prefers-reduced-motion` respected, 360 px minimum width, no horizontal page scroll (fe §6).
- One motion moment only: live mark draw-in on the tape (200 ms); drawers slide 150 ms (fe §3).
- No UI kit, no gradients, one shadow level (drawer only); radius 6/4/999 by hierarchy (fe §3).
- Every screen has empty, loading (skeleton rows) and error states with the copy rules of fe §4.
- `localStorage` only for theme and last filters, always inside try/catch.

## Review Focus

1. **Long and hostile values** (a 5 KB tool argument, an email body containing `<script>` or RTL control characters, a 200-character agent name) render escaped, truncated with "Show all", and never break the layout → F1 (`Value` component), F4, F5.
2. **Session expiry mid-action** (401 while approving) returns to login and back to the same approval without losing the note → F1, F4.
3. **Stale data races** (two analysts decide the same approval; policy activated by someone else) show the 409/412 message from the API and refresh the item → F3, F4.
4. **Very long sessions** (5,000 events) on the tape stay responsive (virtualized list) and keyboard stepping still works → F5.
5. **Dark mode and 360 px width** for the tape (lanes collapse into one column with lane tags) → F5.

---

## File Structure
```
dashboard/
  index.html  vite.config.ts  tsconfig.json  package.json  nginx.conf
  src/
    main.tsx  app/router.tsx  app/AppShell.tsx (rail + main + drawer slot)
    api/schema.d.ts (generated)  api/client.ts  api/queries.ts
    theme/tokens.css  theme/fonts.css  theme/ThemeToggle.tsx
    ui/{Value,DecisionBadge,Drawer,Table,EmptyState,ErrorState,Skeleton,CopyField,ConfirmTyped}.tsx
    features/auth/{LoginPage,useSession}.tsx
    features/agents/{AgentsPage,ConnectAgentFlow,KeysPanel,SnippetTabs}.tsx
    features/policies/{PoliciesPage,PolicyEditor,SimulatePanel}.tsx
    features/approvals/{ApprovalsPage,ApprovalDrawer}.tsx
    features/sessions/{SessionsPage,SessionTape,TapeLane,StepDrawer,ReplayControls}.tsx
    features/alerts/AlertsPage.tsx  features/overview/{OverviewPage,DecisionsChart}.tsx
    features/settings/{SettingsPage,UsersPanel,UpstreamsPanel}.tsx
  e2e/{attack_replay,a11y}.spec.ts
```

### Task F1: Scaffold, tokens, API client, auth shell

**Files:** Create everything under `dashboard/` except `features/*` beyond `auth`; Test `src/ui/*.test.tsx`, `src/features/auth/*.test.tsx`

**Interfaces:**
- Consumes: `agentshield/openapi.json` (B16).
- Produces: `api` client (`fetch` wrapper adding `X-CSRF-Token`, parsing `application/problem+json` into `ApiProblem {code, detail, errors}`); `useSession()`; `<AppShell>`; UI primitives `Value` (literal values: mono, escaped, truncation + "Show all", copy), `DecisionBadge(decision)`, `Drawer`, `Table` (keyset "Load more" using `next_cursor`), `EmptyState`, `ErrorState`, `Skeleton`, `CopyField`, `ConfirmTyped`; theme toggle.

- [ ] **Step 1: Write the design token plan check** — before code, write the fe §2 tokens into `theme/tokens.css` and a 1-page `dashboard/DESIGN_NOTES.md` recording the frontend-design skill's review pass (what was rejected as default and why), so later tasks don't drift.
- [ ] **Step 2: Write failing tests** — `DecisionBadge` renders icon + word for each decision and uses `--recorder` only for `block`; `Value` escapes `<script>`, strips bidi controls for display (keeps them in copy), truncates > 300 chars with "Show all" (Review Focus 1); `api` maps a 412 problem to `ApiProblem.code === "precondition_failed"`; 401 anywhere redirects to `/login?next=<path>` and returns after login (Review Focus 2); theme toggle survives `localStorage` throwing.
- [ ] **Step 3: Run** `npm test` → FAIL. **Step 4: Implement**; `npm run gen:api` generates `schema.d.ts`.
- [ ] **Step 5: Run** tests, `tsc --noEmit`, `eslint` → PASS. **Commit** `feat(dashboard): scaffold, tokens, api client and auth shell`.

### Task F2: Agents and connection flow

**Files:** `features/agents/*`, tests alongside.
**Interfaces:** Consumes `/v1/admin/agents`, `…/keys`, `…/revoke`, `…/snippet`, `/v1/admin/events?agent=`.
- [ ] **Step 1: Failing tests** — agents table with status, mode, last seen; "Connect agent" is a 3-step sequence (create → key shown once with copy + warning → snippet tabs Python OpenAI / Python Anthropic / curl / Claude Code env (API `lang=python-openai|python-anthropic|curl|claude-code`)); after closing, the key is masked (`ask_live_abcd…`) and cannot be shown again; "Send a test request" polls events for that agent and shows the first one; slug validation mirrors `^[a-z0-9][a-z0-9-]{1,62}$`; revoke uses `ConfirmTyped` and toasts "Key revoked"; **Rotate key** asks for an overlap (default 24 h), shows the new key once, toasts "Key rotated".
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(dashboard): agents and connect-agent flow`.

### Task F3: Policies editor and simulator

**Files:** `features/policies/*`.
**Interfaces:** Consumes policy versions, simulate, activate (with `If-Match`).
- [ ] **Step 1: Failing tests** — CodeMirror YAML editor; "Save as new version" shows server `errors[]` as line markers with the API message; "Simulate on last 7 days" lists changed decisions (old → new badge, link to the session tape step); **Activate** requires typing the agent slug when the simulation shows any change from block/ask → allow; 412 on activate shows "This agent's policy changed since you opened it. Reload to see the latest version." and refreshes (Review Focus 3); toast "Policy v4 is active".
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(dashboard): policy editor with validation, simulation and safe activation`.

### Task F4: Approvals

**Files:** `features/approvals/*`.
**Interfaces:** Consumes `/v1/admin/approvals`, `…/{id}/decision`; polls every 5 s.
- [ ] **Step 1: Failing tests** — pending table sorted by time left; drawer shows tool, arguments as a definition list via `Value`, rule id, session risk, countdown, link to the tape; **no model text is rendered anywhere in the drawer** (test feeds an approval whose session contains model text and asserts it's absent); Approve / Deny with optional note, keyboard `a`/`d` with confirm; 409 shows "Already decided by <name>" and refreshes (Review Focus 3); 401 mid-decision keeps the note in a draft and restores it after login (Review Focus 2); expired items move out with "Expired — counted as denied".
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(dashboard): approval queue`.

### Task F5: Sessions list and the session tape (replay)

**Files:** `features/sessions/*`.
**Interfaces:** Consumes sessions, timeline, replay, export, incidents.
- [ ] **Step 1: Failing tests** — five lanes (Input, Scan, Policy, Tool, Model) with each event type mapped to one lane (mapping table in `TapeLane.tsx` tested exhaustively against the canonical event-type list in arch §4.2: Input ← `request.received`, `content.untrusted`; Scan ← `content.scanned`; Policy ← `policy.decision`, `budget.exceeded`, `budget.price_missing`, `approval.*`; Tool ← `tool.requested`, `tool.rewritten`; Model ← `model.response`; `error`/`audit.*` shown as full-width rule lines; `mcp.*` → Tool and `shadow.*` → Input are mapped now so the test stays exhaustive when stages 5–6 add them); blocked step has the orange lane-edge bar and the word "Blocked"; ←/→ step the cursor, Enter opens `StepDrawer` with the recorded payload (or "Payload purged after 30 days" when `payload_available=false`); "Re-check with policy vN" shows ghost marks only on changed steps; 5,000-event fixture renders with virtualization and stepping stays < 50 ms per step (Review Focus 4); at 360 px lanes collapse to one column with lane tags; dark-mode snapshot (Review Focus 5); chain status line ("Chain verified" / "Chain broken at seq N"); Export JSON downloads the API export; Mark as incident creates one and toasts "Incident created"; live mode draws new marks with the single 200 ms motion, none under reduced motion.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5: Commit** `feat(dashboard): session tape with replay and policy re-check`.

### Task F6: Overview, alerts, settings, end-to-end and accessibility

**Files:** `features/{overview,alerts,settings}/*`, `e2e/attack_replay.spec.ts`, `e2e/a11y.spec.ts`, `dashboard/Dockerfile`, `nginx.conf`.
**Interfaces:** Consumes stats, alerts, settings, users, upstreams; the E2E consumes the Compose stack and `agentshield seed-demo` (B17) and the demo runner (E3).
- [ ] **Step 1: Load the `dataviz` skill**, then write failing tests — Overview "Needs you" list first (pending approvals, new blocks, chain/budget problems) then a 24 h stacked bar chart of decisions per hour using only the three status colors; alerts table filters by severity/kind/agent and links to the tape; settings: users + roles, upstreams (API key field write-only: shows "Key saved" never the value), webhook URL (server validation errors shown), retention (cannot go below floors), `on_malicious`.
- [ ] **Step 2: E2E** `attack_replay.spec.ts`: log in → connect agent → run `demo/email_agent/run_protected.py` against the stack → alert appears → open tape → step to the block → replay with relaxed policy shows the ghost "Cleared" mark. `a11y.spec.ts`: axe has no serious/critical violations on every page in light and dark.
- [ ] **Step 3–4:** fail → implement → pass (E2E in CI against Compose).
- [ ] **Step 5: Commit** `feat(dashboard): overview, alerts, settings and e2e attack replay`.

## Self-Review
- **Spec coverage:** fe §2.3 screens → F2–F6; tape + replay + simulator visual → F5 (+F3); principles 1–5 → F1 badge, F4 no-prose test, F3 simulate-before-activate, F2 key-once, empty states in F1 primitives; quality floor → F1 + F6 a11y; screens→API map fe §7 → each task's Interfaces.
- **Type consistency:** generated `schema.d.ts` is the only source of API types; `ApiProblem`, `DecisionBadge`, `Value`, `Drawer`, `Table` are defined in F1 and reused by name.
- **Review Focus:** each of the five items has a named test in its task.
