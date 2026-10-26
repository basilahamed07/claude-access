import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EditorView } from "@codemirror/view";
import { act } from "react";
import { describe, expect, it } from "vitest";
import { Route, Routes } from "react-router-dom";
import PoliciesPage from "./PoliciesPage";
import { editorText } from "./YamlEditor";
import { loosened } from "./SimulatePanel";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const AGENT = { id: "a1", slug: "pay-bot", name: "Pay bot", owner: "o", purpose: "", risk_tier: "medium", mode: "enforce", key_mode: "stored", status: "active",
  created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z", key_count: 1, active_policy_version: 3, last_seen_at: null, upstream_id: null };
const V = (version: number, yaml: string, active = false) => ({ version, yaml, active, created_at: "2026-10-2" + (version % 9) + "T10:00:00Z", created_by: "u1", sha256: "x".repeat(64) });
const base = {
  "GET /v1/auth/me": json(ME),
  "GET /v1/admin/agents": { items: [AGENT] },
  "GET /v1/admin/agents/pay-bot": json(AGENT, { headers: { etag: '"agent-etag-1"' } }),
  "GET /v1/admin/agents/pay-bot/policy/versions": [V(3, "version: 1\nrules: []\n", true), V(2, "version: 1\n"), V(1, "version: 1\n")],
  "GET /v1/admin/agents/pay-bot/policy/versions/3": V(3, "version: 1\nrules: []\n", true),
  "GET /v1/admin/agents/pay-bot/policy/versions/2": V(2, "version: 1\n# old\n"),
  "GET /v1/admin/agents/pay-bot/policy/versions/4": V(4, "version: 1\n# new\n"),
};
const SIM = (diffs: object[]) => ({ version: 4, sessions: 2, compared: 40, skipped: 0, changed: diffs.length, newly_allowed: diffs.length, newly_blocked: 0, newly_asked: 0, diffs, truncated: false });
const STEP = { seq: 7, session_id: "s-111", ts: "2026-10-25T10:00:00Z", trace_id: "t-1", tool: "send_email", recorded_decision: "block", replay_decision: "allow", replay_rule: "allow-any-send", changed: true };

const ui = () => renderApp(<Routes><Route path="/policies/:slug" element={<PoliciesPage />} /><Route path="*" element={<PoliciesPage />} /></Routes>, { path: "/policies/pay-bot" });
const editor = () => EditorView.findFromDOM(document.querySelector(".cm-editor") as HTMLElement)!;
const setDoc = async (text: string) => { await act(async () => { const v = editor(); v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text } }); }); };

describe("policies", () => {
  it("loads the active version into the editor", async () => {
    mockApi({ ...base });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    expect(screen.getByRole("button", { name: "Save as new version" })).toBeDisabled();
    expect(within(screen.getByRole("list", { name: "Versions" })).getByText("Active")).toBeInTheDocument();
  });

  it("shows the server's line errors on the editor and says what to do", async () => {
    mockApi({ ...base, "POST /v1/admin/agents/pay-bot/policy/versions": problem(422, "policy_invalid", "Line 14: unknown operator 'contains'. Use 'regex' or 'in'.",
      { errors: [{ line: 14, path: "rules[1].when.op", message: "unknown operator 'contains'. Use 'regex' or 'in'." }] }) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await setDoc(Array.from({ length: 16 }, (_, i) => `# line ${i + 1}`).join("\n"));
    await userEvent.click(screen.getByRole("button", { name: "Save as new version" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Policy not saved. Line 14: unknown operator 'contains'. Use 'regex' or 'in'.");
    await waitFor(() => expect(document.querySelector(".cm-lint-marker-error, .cm-lintRange-error")).not.toBeNull());
  });

  it("saves as a new version and selects it", async () => {
    const { calls } = mockApi({ ...base, "POST /v1/admin/agents/pay-bot/policy/versions": json(V(4, "version: 1\n# new\n"), { status: 201 }) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await setDoc("version: 1\n# new\n");
    await userEvent.click(screen.getByRole("button", { name: "Save as new version" }));
    expect(await screen.findByText("Saved as v4")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ yaml: "version: 1\n# new\n" });
  });

  it("simulates and lists changed decisions with a link to the tape step", async () => {
    mockApi({ ...base, "POST /v1/admin/agents/pay-bot/policy/simulate": SIM([STEP]) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await userEvent.click(screen.getByRole("button", { name: "Simulate on last 7 days" }));
    const panel = await screen.findByRole("region", { name: /Simulation of policy v3/ });
    expect(within(panel).getByText(/1 would change/)).toBeInTheDocument();
    expect(within(panel).getByText("Blocked")).toBeInTheDocument();
    expect(within(panel).getByText("Cleared")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Open on the tape" })).toHaveAttribute("href", "/sessions/s-111?step=7");
  });

  it("only a loosening change is detected as loosening", () => {
    expect(loosened(SIM([STEP]) as never)).toHaveLength(1);
    expect(loosened(SIM([{ ...STEP, recorded_decision: "allow", replay_decision: "block" }]) as never)).toHaveLength(0);
    expect(loosened(null)).toEqual([]);
  });

  it("activating a loosening version needs the agent id typed; a safe one does not", async () => {
    const { calls } = mockApi({ ...base,
      "POST /v1/admin/agents/pay-bot/policy/simulate": SIM([STEP]),
      "POST /v1/admin/agents/pay-bot/policy/versions/2/activate": json(V(2, "x", true)) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await userEvent.click(within(screen.getByRole("list", { name: "Versions" })).getByRole("button", { name: /v2/ }));
    await waitFor(() => expect(editorText(document.body)).toContain("# old"));
    await userEvent.click(screen.getByRole("button", { name: "Activate policy" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/This loosens the policy/)).toBeInTheDocument();
    const go = within(dialog).getByRole("button", { name: "Activate policy" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type/), "pay-bot");
    await userEvent.click(go);
    expect(await screen.findByText("Policy v2 is active")).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith("/2/activate"))!.headers["If-Match"]).toBe('"agent-etag-1"');
  });

  it("a safe activation goes straight through", async () => {
    mockApi({ ...base, "POST /v1/admin/agents/pay-bot/policy/simulate": SIM([]), "POST /v1/admin/agents/pay-bot/policy/versions/2/activate": json(V(2, "x", true)) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await userEvent.click(within(screen.getByRole("list", { name: "Versions" })).getByRole("button", { name: /v2/ }));
    await userEvent.click(screen.getByRole("button", { name: "Activate policy" }));
    expect(await screen.findByText("Policy v2 is active")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("a 412 on activate says the policy changed and refreshes", async () => {
    let agentCalls = 0;
    mockApi({ ...base, "GET /v1/admin/agents/pay-bot": () => { agentCalls++; return json(AGENT, { headers: { etag: `"e${agentCalls}"` } }); },
      "POST /v1/admin/agents/pay-bot/policy/simulate": SIM([]),
      "POST /v1/admin/agents/pay-bot/policy/versions/2/activate": problem(412, "precondition_failed", "The resource changed") });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    await userEvent.click(within(screen.getByRole("list", { name: "Versions" })).getByRole("button", { name: /v2/ }));
    await userEvent.click(screen.getByRole("button", { name: "Activate policy" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("This agent's policy changed since you opened it. Reload to see the latest version.");
    await waitFor(() => expect(agentCalls).toBeGreaterThan(1));
  });

  it("offers a starter policy when the agent has none", async () => {
    mockApi({ ...base, "GET /v1/admin/agents/pay-bot": json({ ...AGENT, active_policy_version: null }), "GET /v1/admin/agents/pay-bot/policy/versions": [] });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("default deny"));
    expect(screen.getByText(/No versions yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save as new version" })).toBeEnabled();
  });

  it("analysts can simulate but not save or activate", async () => {
    mockApi({ ...base, "GET /v1/auth/me": json({ ...ME, role: "analyst" }) });
    ui();
    await waitFor(() => expect(editorText(document.body)).toContain("rules: []"));
    expect(screen.queryByRole("button", { name: "Save as new version" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Activate policy" })).toBeNull();
    expect(screen.getByRole("button", { name: "Simulate on last 7 days" })).toBeEnabled();
  });
});
