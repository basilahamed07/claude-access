import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Route, Routes } from "react-router-dom";
import ShadowPage from "./ShadowPage";
import { chunkLog, MAX_CHUNK_LINES } from "./chunks";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const TOOL = { id: "t1", domain: "chat.openai.com", vendor: "OpenAI", category: "chat", risk: "high", classification: "unknown", team: "Marketing", source: "proxy", reason: "catalog",
  hits: 1200, bytes_out: 0, users_count: 14, first_seen: "2026-10-20T10:00:00Z", last_seen: "2026-10-26T10:00:00Z", suggested_alternative: null };
const BLOCKED = { ...TOOL, id: "t2", domain: "claude.ai", vendor: "Anthropic", classification: "blocked", team: null, reason: "heuristic: the path is a model API" };
const base = (extra: Record<string, unknown> = {}, me = ME) => ({ "GET /v1/auth/me": json(me), "GET /v1/admin/ai-tools": [TOOL, BLOCKED], ...extra });
const ui = () => renderApp(<Routes><Route path="/shadow" element={<ShadowPage />} /></Routes>, { path: "/shadow" });

describe("log chunking", () => {
  it("splits big files, caps line length, and repeats the CSV header in every piece", () => {
    const lines = Array.from({ length: MAX_CHUNK_LINES + 3 }, (_, i) => `row${i}`);
    const chunks = chunkLog(lines.join("\n"), "squid");
    expect(chunks.map((c) => c.length)).toEqual([MAX_CHUNK_LINES, 3]);
    const csv = chunkLog(["ts,host", ...lines].join("\n"), "csv");
    expect(csv.every((c) => c[0] === "ts,host")).toBe(true);
    expect(chunkLog("x".repeat(9000), "squid")[0][0]).toHaveLength(4000);
    expect(chunkLog("\n \n", "squid")).toEqual([]);
  });
});

describe("Shadow AI", () => {
  it("shows what was seen in words, with people as an estimate and no raw names", async () => {
    mockApi(base());
    ui();
    expect(await screen.findByText("chat.openai.com")).toBeInTheDocument();
    expect(screen.getAllByText("about 14")).toHaveLength(2);
    expect(screen.getByText("Not reviewed", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText(/found by its API path/)).toBeInTheDocument();
    expect(screen.getByText("unassigned")).toBeInTheDocument();
  });

  it("an admin classifies a tool; the choices exclude its current status", async () => {
    const { calls } = mockApi(base({ "PATCH /v1/admin/ai-tools/t1": { ...TOOL, classification: "blocked" } }));
    ui();
    await screen.findByText("chat.openai.com");
    expect(screen.queryByRole("button", { name: "Block claude.ai" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Block chat.openai.com" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ classification: "blocked" }));
  });

  it("filters by status and shows the API's reason when saving fails", async () => {
    const { calls } = mockApi(base({ "PATCH /v1/admin/ai-tools/t1": problem(500, "internal", "Internal error") }));
    ui();
    await screen.findByText("chat.openai.com");
    await userEvent.click(screen.getByRole("button", { name: "Blocked" }));
    await waitFor(() => expect(calls.some((c) => c.path.includes("classification=blocked"))).toBe(true));
    await userEvent.click(screen.getByRole("button", { name: "All" }));
    await userEvent.click(await screen.findByRole("button", { name: "Approve chat.openai.com" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Internal error");
  });

  it("a viewer can read the inventory but has no controls", async () => {
    mockApi(base({}, { ...ME, role: "viewer" }));
    ui();
    await screen.findByText("chat.openai.com");
    expect(screen.queryByRole("button", { name: /^(Approve|Block|Tolerate) / })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Upload a log file" })).not.toBeInTheDocument();
  });

  it("the empty state explains how to get data in", async () => {
    mockApi(base({ "GET /v1/admin/ai-tools": [] }));
    ui();
    expect(await screen.findByText("No AI tools seen yet")).toBeInTheDocument();
  });

  it("creates an ingest token that is shown once, and revokes one", async () => {
    const { calls } = mockApi(base({
      "GET /v1/admin/tokens": [{ id: "k1", prefix: "asu_abcd1234", label: "squid", created_at: "x", revoked_at: null }],
      "POST /v1/admin/tokens": json({ id: "k2", prefix: "asu_zzzz9999", label: "dns", created_at: "x", revoked_at: null, token: "asu_zzzz9999SECRET" }, { status: 201 }),
      "DELETE /v1/admin/tokens/k1": new Response(null, { status: 204 }),
    }));
    ui();
    await userEvent.click(await screen.findByRole("button", { name: "Create ingest token" }));
    await userEvent.type(await screen.findByLabelText("What will use it"), "dns");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    expect(await screen.findByDisplayValue("asu_zzzz9999SECRET")).toBeInTheDocument();
    expect(screen.getByText(/not shown again/)).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ label: "dns" });
    await userEvent.click(screen.getByRole("button", { name: "Revoke squid" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });

  it("uploads a file in pieces with a stable batch id and reports what was read", async () => {
    const { calls } = mockApi(base({ "POST /v1/ingest/logs": json({ batch_id: "b", duplicate: false, accepted: 2, rejected: 1, reasons: [], tools_seen: 1, new_tools: 1 }) }));
    ui();
    await userEvent.click(await screen.findByRole("button", { name: "Upload a log file" }));
    await userEvent.selectOptions(await screen.findByLabelText("Log format"), "dns");
    await userEvent.type(screen.getByLabelText(/Team/), "Sales");
    const file = new File(["1700000000 laptop api.mistral.ai\n1700000001 laptop example.org\nbad\n"], "dns.log", { type: "text/plain" });
    await userEvent.upload(screen.getByLabelText("Log file"), file);
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));
    expect(await screen.findByText(/Read 2 lines, skipped 1/)).toBeInTheDocument();
    const sent = calls.find((c) => c.method === "POST")!.body as Record<string, unknown>;
    expect(sent).toMatchObject({ source: "dns", format: "dns", team: "Sales" });
    expect(sent.batch_id).toMatch(/^upload-[0-9a-f]{16}-dns-0$/);
    expect(sent.lines).toHaveLength(3);
  });
});
