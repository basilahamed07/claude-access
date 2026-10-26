import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import OverviewPage from "./OverviewPage";
import { hourlyBuckets, niceMax } from "./DecisionsChart";
import AlertsPage from "../alerts/AlertsPage";
import { ME, json, mockApi, renderApp } from "../../test/helpers";

const HOUR = 3_600_000;
const hourStart = (offset: number) => new Date(Math.floor(Date.now() / HOUR) * HOUR - offset * HOUR).toISOString();
const ALERT = (over: object = {}) => ({ kind: "blocked_call", ts: new Date().toISOString(), seq: 7, severity: "high", summary: "send_email block by deny-external-send", agent_slug: "email-reader-01", session_id: "s9", trace_id: "t", rule_id: "deny-external-send", ...over });
const STATS = { window: "24h", calls: 12, allowed: 8, blocked: 3, asked: 1, malicious_scans: 1, approvals_pending: 1, active_sessions: 2, risky_sessions: 1, top_rules: [], top_agents: [],
  series: [{ ts: hourStart(1), allowed: 5, blocked: 2, asked: 0 }, { ts: hourStart(0), allowed: 3, blocked: 1, asked: 1 }] };
const base = (extra: Record<string, unknown> = {}) => ({ "GET /v1/auth/me": json(ME), "GET /v1/admin/stats/overview": STATS, "GET /v1/admin/alerts": { items: [ALERT()] },
  "GET /v1/admin/approvals": { items: [{ id: "a1" }, { id: "a2" }] }, ...extra });

describe("chart data", () => {
  it("fills quiet hours with zeros so 24 bars always exist", () => {
    const b = hourlyBuckets([{ ts: hourStart(2), allowed: 4, asked: 1, blocked: 0 }], Date.now());
    expect(b).toHaveLength(24);
    expect(b[21]).toMatchObject({ allowed: 4, asked: 1 });
    expect(b.filter((x) => x.allowed + x.asked + x.blocked === 0)).toHaveLength(23);
    expect(b[23].start).toBe(Math.floor(Date.now() / HOUR) * HOUR);
  });
  it("picks a readable axis maximum", () => { expect(niceMax(0)).toBe(4); expect(niceMax(7)).toBe(10); expect(niceMax(42)).toBe(50); });
});

describe("overview", () => {
  it("puts 'Needs you' before the chart", async () => {
    mockApi(base());
    renderApp(<OverviewPage />);
    const needs = await screen.findByRole("heading", { name: "Needs you" });
    const chart = await screen.findByRole("heading", { name: "Decisions per hour" });
    expect(needs.compareDocumentPosition(chart) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(await screen.findByText("2 actions are waiting for an approval")).toBeInTheDocument();
    expect(screen.getByText(/Action blocked/)).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Open the tape" })).toHaveAttribute("href", "/sessions/s9");
  });
  it("draws status-coloured stacked bars with a legend that has icon and word, and a table view", async () => {
    mockApi(base());
    const { container } = renderApp(<OverviewPage />);
    const legend = await screen.findByRole("list", { name: "Legend" });
    for (const w of ["Cleared", "Holding", "Blocked"]) expect(within(legend).getByText(w)).toBeInTheDocument();
    expect(legend.querySelectorAll("svg")).toHaveLength(3);
    const fills = new Set([...container.querySelectorAll("figure rect[fill]")].map((r) => r.getAttribute("fill")).filter((f) => f !== "transparent"));
    expect([...fills].sort()).toEqual(["var(--cleared)", "var(--holding)", "var(--recorder)"]);
    expect(screen.getByRole("img", { name: /Stacked bars/ })).toHaveAccessibleName(/12 in total|11 in total/);
    await userEvent.click(screen.getByRole("button", { name: "View as table" }));
    const table = screen.getByRole("region", { name: "Decisions per hour as a table" });
    expect(within(table).getAllByRole("row")).toHaveLength(25);
    await userEvent.click(screen.getByRole("button", { name: "View as chart" }));
  });
  it("hover and focus show the exact counts", async () => {
    mockApi(base());
    const { container } = renderApp(<OverviewPage />);
    await screen.findByRole("list", { name: "Legend" });
    const bars = container.querySelectorAll("g.barg");
    expect(bars).toHaveLength(24);
    (bars[23] as SVGGElement).focus();
    expect(await screen.findByText("Blocked: 1")).toBeInTheDocument();
    expect(screen.getByText("Cleared: 3")).toBeInTheDocument();
  });
  it("says so when nothing needs attention", async () => {
    mockApi(base({ "GET /v1/admin/alerts": { items: [] }, "GET /v1/admin/approvals": { items: [] } }));
    renderApp(<OverviewPage />);
    expect(await screen.findByText("Nothing needs you right now")).toBeInTheDocument();
  });
  it("viewers do not ask for approvals", async () => {
    const { calls } = mockApi(base({ "GET /v1/auth/me": json({ ...ME, role: "viewer" }) }));
    renderApp(<OverviewPage />);
    await screen.findByRole("heading", { name: "Decisions per hour" });
    expect(calls.some((c) => c.path.startsWith("/v1/admin/approvals"))).toBe(false);
  });
});

describe("alerts", () => {
  const alerts = [ALERT(), ALERT({ seq: 8, kind: "malicious_content", agent_slug: "pay-bot", severity: "critical", summary: "email m-1 judged malicious" }),
    ALERT({ seq: 9, kind: "audit_gap", agent_slug: null, session_id: null, severity: "medium", summary: "2 events were delayed" })];
  const table = async () => within(await screen.findByRole("region", { name: "Alerts" }));
  it("lists alerts, filters by severity and agent, and links to the tape step", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/alerts": { items: alerts } });
    renderApp(<AlertsPage />);
    const t = await table();
    expect(t.getByText("Attack found in content")).toBeInTheDocument();
    expect(t.getAllByRole("link", { name: "Open the tape" })[0]).toHaveAttribute("href", "/sessions/s9?step=7");
    await userEvent.selectOptions(screen.getByLabelText("Severity"), "critical");
    expect(t.queryByText("Action blocked")).toBeNull();
    expect(t.getByText("Attack found in content")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Severity"), "");
    await userEvent.selectOptions(screen.getByLabelText("Agent"), "email-reader-01");
    expect(t.queryByText("Attack found in content")).toBeNull();
    expect(t.getByText("Action blocked")).toBeInTheDocument();
  });
  it("sends the kind to the server", async () => {
    const { calls } = mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/alerts": { items: alerts } });
    renderApp(<AlertsPage />);
    await table();
    await userEvent.selectOptions(screen.getByLabelText("Kind"), "audit_gap");
    await waitFor(() => expect(calls.some((c) => c.path.includes("kind=audit_gap"))).toBe(true));
  });
  it("empty state", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/alerts": { items: [] } });
    renderApp(<AlertsPage />);
    expect(await screen.findByText("No alerts")).toBeInTheDocument();
  });
});
