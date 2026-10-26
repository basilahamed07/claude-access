import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Route, Routes } from "react-router-dom";
import SessionsPage from "./SessionsPage";
import { LANES, placementOf } from "./TapeLane";
import { ghostsFor } from "./tape";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const backendTypes = [...readFileSync("../agentshield/src/agentshield/contracts/events.py", "utf8").matchAll(/= "([a-z_.]+)"$/gm)].map((m) => m[1]).filter((t) => t.includes(".") || t === "error");

describe("lane mapping", () => {
  it("has a lane (or rule line) for every event type the backend can emit", () => {
    expect(backendTypes.length).toBeGreaterThan(20);
    for (const t of backendTypes) {
      const p = placementOf(t);
      expect(p.kind === "rule" || LANES.includes(p.lane), t).toBe(true);
    }
  });
  it("puts each type where the design says", () => {
    const lane = (t: string) => { const p = placementOf(t); return p.kind === "lane" ? p.lane : "rule"; };
    expect(lane("request.received")).toBe("Input"); expect(lane("content.untrusted")).toBe("Input");
    expect(lane("content.scanned")).toBe("Scan");
    for (const t of ["policy.decision", "budget.exceeded", "budget.price_missing", "approval.requested", "approval.decided", "approval.notify_failed"]) expect(lane(t), t).toBe("Policy");
    expect(lane("tool.requested")).toBe("Tool"); expect(lane("tool.rewritten")).toBe("Tool"); expect(lane("mcp.tool_call")).toBe("Tool");
    expect(lane("model.response")).toBe("Model");
    expect(lane("shadow.dlp_hit")).toBe("Input");
    expect(lane("error")).toBe("rule"); expect(lane("audit.gap")).toBe("rule"); expect(lane("audit.checkpoint")).toBe("rule");
  });
});

const SESSION = { id: "s9", agent_slug: "email-reader-01", end_user: "alice@acme.com", user_request: "Summarize my unread mail", risk_score: 0.88,
  started_at: "2026-10-26T10:41:00Z", last_seen_at: "2026-10-26T10:41:05Z", calls: 2, blocked: 1 };
let seq = 0;
const EV = (type: string, extra: object = {}) => ({ seq: ++seq, ts: `2026-10-26T10:41:${String(seq % 60).padStart(2, "0")}Z`, id: `e${seq}`, trace_id: "t-1", session_id: "s9", agent_slug: "email-reader-01",
  end_user: null, module: "gateway", type, decision: null, rule_id: null, reason: null, severity: "info", summary: `${type} happened`, payload_truncated: false, payload_available: true, hash: "ab".repeat(32), payload: { n: seq }, ...extra });
const ATTACK = () => {
  seq = 0;
  return [EV("request.received", { summary: "user request" }), EV("tool.requested", { summary: "read_email requested (read)" }),
    EV("policy.decision", { module: "policy", decision: "allow", rule_id: "allow-read-mail", summary: "read_email allow by allow-read-mail" }),
    EV("content.scanned", { module: "injection", severity: "high", summary: "email m-441 judged malicious", payload: { source: "email", id: "m-441", verdict: "malicious", risk_after: 0.88 } }),
    EV("tool.requested", { summary: "send_email requested (external)", payload: { tool: "send_email" } }),
    EV("policy.decision", { module: "policy", decision: "block", rule_id: "deny-external-send", severity: "high", reason: "External email is not permitted", summary: "send_email block by deny-external-send" }),
    EV("tool.rewritten", { decision: "block", summary: "send_email replaced with a block notice" }),
    EV("audit.gap", { module: "audit", severity: "medium", summary: "2 events were delayed" })];
};
const timeline = (events: object[]) => ({ session: SESSION, traces: [{ trace_id: "t-1", started_at: "2026-10-26T10:41:00Z", events }], truncated: false });
const EXPORT = (ok = true) => ({ exported_at: "x", session: SESSION, events: [], chain_head: { last_seq: 8, last_hash: "9c1e".padEnd(64, "0") },
  verification: ok ? { verified: true, checked: 8, first_seq: 1, last_seq: 8 } : { verified: false, checked: 3, first_bad_seq: 4, reason: "hash mismatch" } });
const base = (events: object[] = ATTACK(), extra: Record<string, unknown> = {}) => ({
  "GET /v1/auth/me": json(ME), "GET /v1/admin/sessions/s9/timeline": timeline(events), "GET /v1/admin/sessions/s9/export.json": EXPORT(),
  "GET /v1/admin/agents/email-reader-01/policy/versions": [{ version: 4, active: true, created_at: "x", created_by: "u", sha256: "x" }, { version: 3, active: false, created_at: "x", created_by: "u", sha256: "x" }],
  "GET /v1/admin/agents": { items: [] }, ...extra });
const ui = (path = "/sessions/s9") => renderApp(<Routes><Route path="/sessions" element={<SessionsPage />} /><Route path="/sessions/:id" element={<SessionsPage />} /></Routes>, { path });

describe("sessions list", () => {
  it("shows outcome, agent, user, request and risk", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [] }, "GET /v1/admin/sessions": { items: [SESSION, { ...SESSION, id: "s2", blocked: 0, calls: 3, risk_score: 0 }] } });
    ui("/sessions");
    expect(await screen.findByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("Cleared")).toBeInTheDocument();
    expect(screen.getAllByText("email-reader-01")).toHaveLength(2);
    expect(screen.getByText("0.88")).toBeInTheDocument();
  });
  it("empty state points to connecting an agent", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [] }, "GET /v1/admin/sessions": { items: [] } });
    ui("/sessions");
    expect(await screen.findByText("No sessions yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connect agent" })).toBeInTheDocument();
  });
});

describe("session tape", () => {
  it("draws every event, marks the blocked step with the word Blocked, and shows chain status", async () => {
    mockApi(base());
    ui();
    const grid = await screen.findByRole("grid", { name: "Session events" });
    expect(within(grid).getAllByRole("row")).toHaveLength(8);
    expect(within(grid).getAllByText("Blocked").length).toBeGreaterThan(0);
    const blockedRows = grid.querySelectorAll(".trow.is-blocked");
    expect(blockedRows.length).toBe(3);                         // malicious scan, block decision, rewritten call
    expect(await screen.findByText(/Chain verified \(8 events\)/)).toBeInTheDocument();
    expect(screen.getByText(/9c1e0000…/)).toBeInTheDocument();
    expect(within(grid).getByText(/email m-441 judged malicious · risk 0.88/)).toBeInTheDocument();
  });

  it("says when the chain is broken and where", async () => {
    mockApi(base(ATTACK(), { "GET /v1/admin/sessions/s9/export.json": EXPORT(false) }));
    ui();
    expect(await screen.findByText(/Chain broken at seq 4/)).toBeInTheDocument();
  });

  it("arrow keys step the cursor and Enter opens the recorded payload", async () => {
    mockApi(base());
    ui();
    const grid = await screen.findByRole("grid", { name: "Session events" });
    grid.focus();
    const active = () => grid.querySelector(".trow.is-active")!.id;
    expect(active()).toBe("tape-row-0");
    await userEvent.keyboard("{ArrowRight}{ArrowRight}");
    expect(active()).toBe("tape-row-2");
    await userEvent.keyboard("{ArrowLeft}");
    expect(active()).toBe("tape-row-1");
    await userEvent.keyboard("{End}");
    expect(active()).toBe("tape-row-7");
    await userEvent.keyboard("{Home}{ArrowRight}{ArrowRight}{ArrowRight}{ArrowRight}{ArrowRight}{Enter}");
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByRole("heading", { name: "Step 6" })).toBeInTheDocument();
    expect(within(drawer).getByText("deny-external-send")).toBeInTheDocument();
    expect(within(drawer).getByText("External email is not permitted")).toBeInTheDocument();
    expect(within(drawer).getByText("Recorded payload")).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("buttons step too", async () => {
    mockApi(base());
    ui();
    await userEvent.click(await screen.findByRole("button", { name: "Next step" }));
    expect(document.querySelector(".trow.is-active")!.id).toBe("tape-row-1");
    await userEvent.click(screen.getByRole("button", { name: "Previous step" }));
    expect(document.querySelector(".trow.is-active")!.id).toBe("tape-row-0");
    expect(screen.getByRole("button", { name: "Previous step" })).toBeDisabled();
  });

  it("explains a purged payload", async () => {
    const ev = ATTACK().map((e) => ({ ...e, payload: null, payload_available: false }));
    mockApi(base(ev));
    ui();
    const grid = await screen.findByRole("grid", { name: "Session events" });
    grid.focus();
    await userEvent.keyboard("{Enter}");
    expect(await screen.findByText(/Payload purged after 30 days/)).toBeInTheDocument();
  });

  it("starts on ?step=", async () => {
    mockApi(base());
    ui("/sessions/s9?step=5");
    await screen.findByRole("grid", { name: "Session events" });
    await waitFor(() => expect(document.querySelector(".trow.is-active")!.id).toBe("tape-row-4"));
  });

  it("Re-check with policy vN shows ghost marks only on the changed step", async () => {
    const { calls } = mockApi(base(ATTACK(), { "POST /v1/admin/sessions/s9/replay": json({ session_id: "s9", policy_version: 3, compared: 2, skipped: 0, changed: 1, redacted_input: true,
      steps: [{ seq: 2, session_id: "s9", ts: "x", trace_id: "t-1", tool: "read_email", recorded_decision: "allow", replay_decision: "allow", changed: false },
              { seq: 5, session_id: "s9", ts: "x", trace_id: "t-1", tool: "send_email", recorded_decision: "block", replay_decision: "allow", replay_rule: "allow-any-send", changed: true }] }) }));
    ui();
    await screen.findByRole("option", { name: /v3/ });
    await userEvent.selectOptions(screen.getByLabelText("Re-check with policy"), "3");
    await userEvent.click(screen.getByRole("button", { name: "Re-check" }));
    expect(await screen.findByText("1 decision would change under v3.")).toBeInTheDocument();
    const ghosts = document.querySelectorAll(".ghost");
    expect(ghosts).toHaveLength(1);
    expect(ghosts[0]).toHaveTextContent("Would be Cleared");
    expect(ghosts[0].closest(".trow")!.id).toBe("tape-row-5");        // the block decision that followed send_email
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ policy_version: 3 });
  });

  it("ghostsFor ignores unchanged steps and pairs by trace", () => {
    const evs = ATTACK() as never;
    expect(ghostsFor(evs, [{ seq: 2, trace_id: "t-1", changed: false, tool: "x" } as never]).size).toBe(0);
    expect(ghostsFor(evs, [{ seq: 5, trace_id: "other", changed: true, tool: "x" } as never]).size).toBe(0);
  });

  it("Mark as incident creates one and toasts", async () => {
    const { calls } = mockApi(base(ATTACK(), { "POST /v1/admin/incidents": json({ id: "i1", session_id: "s9", title: "t", severity: "high", status: "open", created_by: "u", created_at: "x", updated_at: "x" }, { status: 201 }) }));
    ui();
    await userEvent.click(await screen.findByRole("button", { name: "Mark as incident" }));
    const title = screen.getByLabelText("Title");
    await userEvent.clear(title);
    await userEvent.type(title, "Poisoned invoice email");
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Mark as incident" }));
    expect(await screen.findByText("Incident created")).toBeInTheDocument();
    expect(calls.find((c) => c.path === "/v1/admin/incidents")!.body).toEqual({ session_id: "s9", title: "Poisoned invoice email", severity: "high" });
  });

  it("viewers see envelopes, no payloads, and no analyst actions", async () => {
    mockApi({ ...base(ATTACK().map((e) => ({ ...e, payload: null }))), "GET /v1/auth/me": json({ ...ME, role: "viewer" }) });
    ui();
    const grid = await screen.findByRole("grid", { name: "Session events" });
    expect(screen.queryByRole("button", { name: "Export JSON" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Mark as incident" })).toBeNull();
    expect(screen.queryByLabelText("Re-check with policy")).toBeNull();
    grid.focus();
    await userEvent.keyboard("{Enter}");
    expect(await screen.findByText("Payloads need the analyst role.")).toBeInTheDocument();
  });

  it("shows the API's error and a retry when the session is missing", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/sessions/s9/timeline": problem(404, "not_found", "Session not found") });
    ui();
    expect(await screen.findByRole("alert")).toHaveTextContent("Session not found");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("renders hostile summaries as text", async () => {
    mockApi(base([EV("request.received", { summary: "<img src=x onerror=alert(1)>‮evil" })]));
    ui();
    await screen.findByRole("grid", { name: "Session events" });
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("a very long session", () => {
  it("keeps 5,000 events virtualised and stepping fast", async () => {
    seq = 0;
    const many = Array.from({ length: 5000 }, (_, i) => EV(i % 3 === 0 ? "tool.requested" : i % 3 === 1 ? "policy.decision" : "model.response", { decision: i % 3 === 1 ? (i % 7 === 1 ? "block" : "allow") : null }));
    mockApi(base(many));
    ui();
    const grid = await screen.findByRole("grid", { name: "Session events" });
    expect(grid).toHaveAttribute("aria-rowcount", "5000");
    expect(within(grid).getAllByRole("row").length).toBeLessThan(80);
    grid.focus();
    const t0 = performance.now();
    for (let i = 0; i < 30; i++) await act(async () => { fireEvent.keyDown(grid, { key: "ArrowRight" }); });
    const per = (performance.now() - t0) / 30;
    expect(grid.querySelector(".trow.is-active")!.id).toBe("tape-row-30");
    expect(per).toBeLessThan(50);
    await act(async () => { fireEvent.keyDown(grid, { key: "End" }); });
    expect(grid.querySelector(".trow.is-active")!.id).toBe("tape-row-4999");
    expect(within(grid).getAllByRole("row").length).toBeLessThan(80);
  });
});
