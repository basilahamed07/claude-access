import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Route, Routes } from "react-router-dom";
import McpPage from "./McpPage";
import { parseManifest } from "./RegisterServer";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const SERVER = { id: "s1", name: "mail", owner: "ops@acme.com", purpose: "mail", url: "https://mail.mcp.test/mcp", pinned_version: "unversioned", verdict: "pending",
  declared_capabilities: ["external"], allowed_tools: null, fingerprint: "ab".repeat(32), approved_fingerprint: null, tool_count: 2, has_auth: false, scanned_at: "2026-10-26T10:00:00Z", created_at: "x", updated_at: "x" };
const TOOLS = [{ name: "read_email", description: "Reads mail" }, { name: "send_email", description: "Sends mail" }];
const REPORT = (over: object = {}) => ({ recommended_verdict: "approved", findings: [], capabilities: { send_email: ["external"] },
  checks: [{ id: "tool_descriptions", name: "Tool descriptions scanned", ran: true }, { id: "sandbox", name: "Run in a locked-down sandbox", ran: false }],
  limitations: ["The sandbox run is not implemented: nothing here proves how the server behaves when called."], ...over });
const DETAIL = (over: object = {}) => ({ ...SERVER, tools: TOOLS, report: REPORT(), ...over });
const base = (extra: Record<string, unknown> = {}) => ({ "GET /v1/auth/me": json(ME), "GET /v1/admin/mcp-servers": [SERVER], "GET /v1/admin/mcp-servers/s1": DETAIL(), ...extra });
const ui = (path = "/mcp") => renderApp(<Routes><Route path="/mcp" element={<McpPage />} /><Route path="/mcp/:id" element={<McpPage />} /></Routes>, { path });

describe("manifest parsing", () => {
  it("accepts a list or an object with tools, and explains what is wrong otherwise", () => {
    expect(parseManifest('[{"name":"a"}]')).toEqual({ tools: [{ name: "a" }] });
    expect(parseManifest('{"tools":[{"name":"a"}]}')).toEqual({ tools: [{ name: "a" }] });
    expect(parseManifest("nope")).toEqual({ error: "That is not valid JSON." });
    expect(parseManifest("[]")).toMatchObject({ error: expect.stringContaining("tools/list") });
    expect(parseManifest('[{"description":"x"}]')).toEqual({ error: 'Every tool needs a "name".' });
  });
});

describe("MCP servers", () => {
  it("lists servers with their verdict in words and the tool count", async () => {
    mockApi(base({ "GET /v1/admin/mcp-servers": [SERVER, { ...SERVER, id: "s2", name: "bad", verdict: "suspended", allowed_tools: ["a"], tool_count: 3 }] }));
    ui();
    expect(await screen.findByText("Pending review")).toBeInTheDocument();
    expect(screen.getByText("Suspended: changed after approval")).toBeInTheDocument();
    expect(screen.getByText("1 of 3")).toBeInTheDocument();
  });

  it("empty state offers to register", async () => {
    mockApi(base({ "GET /v1/admin/mcp-servers": [] }));
    ui();
    expect(await screen.findByText("No MCP servers yet")).toBeInTheDocument();
  });

  it("registers by URL with declared capabilities and the write-only token, then opens the report", async () => {
    const { calls } = mockApi(base({ "POST /v1/admin/mcp-servers": json(DETAIL(), { status: 201 }) }));
    ui();
    await userEvent.click((await screen.findAllByRole("button", { name: "Register server" }))[0]);
    const go = screen.getByRole("button", { name: "Register and scan" });
    expect(go).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Name"), "Mail");
    expect(screen.getByText(/Lowercase letters, numbers and hyphens/)).toHaveClass("err");
    await userEvent.clear(screen.getByLabelText("Name"));
    await userEvent.type(screen.getByLabelText("Name"), "mail");
    await userEvent.type(screen.getByLabelText("Owner"), "ops@acme.com");
    await userEvent.click(screen.getByLabelText(/Send things outside/));
    await userEvent.type(screen.getByLabelText("Server URL"), "https://mail.mcp.test/mcp");
    expect((screen.getByLabelText(/Bearer token/) as HTMLInputElement).type).toBe("password");
    await userEvent.type(screen.getByLabelText(/Bearer token/), "tok-1");
    await userEvent.click(go);
    expect(await screen.findByRole("heading", { name: "MCP server mail" })).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ name: "mail", owner: "ops@acme.com", purpose: "", declared_capabilities: ["external"], url: "https://mail.mcp.test/mcp", auth_token: "tok-1" });
  });

  it("registers a pasted tool list and shows the API's reason when it fails", async () => {
    const { calls } = mockApi(base({ "POST /v1/admin/mcp-servers": problem(502, "upstream_error", "Could not scan this server: the server timed out") }));
    ui();
    await userEvent.click((await screen.findAllByRole("button", { name: "Register server" }))[0]);
    await userEvent.type(screen.getByLabelText("Name"), "pasted");
    await userEvent.type(screen.getByLabelText("Owner"), "me");
    await userEvent.click(screen.getByRole("tab", { name: "Paste the tool list" }));
    await userEvent.click(screen.getByLabelText("Tool list (JSON)"));
    await userEvent.paste('{"tools": [{"name": "lookup"}]}');
    await userEvent.click(screen.getByRole("button", { name: "Register and scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not scan this server: the server timed out");
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ tools: [{ name: "lookup" }] });
    expect((calls.find((c) => c.method === "POST")!.body as Record<string, unknown>).url).toBeUndefined();
  });

  it("the report shows findings in words, what ran and what did not, and treats hostile text as text", async () => {
    mockApi(base({ "GET /v1/admin/mcp-servers/s1": DETAIL({ report: REPORT({ recommended_verdict: "rejected",
      findings: [{ check: "tool_description", severity: "high", message: "search_web: the description contains instructions aimed at the model", tool: "search_web", excerpt: "<img src=x onerror=alert(1)>Before using any other tool" }] }) }) }));
    ui("/mcp/s1");
    const dlg = await screen.findByRole("dialog");
    expect(await within(dlg).findByText("High")).toBeInTheDocument();
    expect(within(dlg).getByText(/contains instructions aimed at the model/)).toBeInTheDocument();
    expect(within(dlg).getByText(/Run in a locked-down sandbox/).parentElement).toHaveTextContent("not run");
    expect(within(dlg).getByText(/sandbox run is not implemented/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("a rejected recommendation needs an acknowledgement before the approve button works", async () => {
    const { calls } = mockApi(base({ "GET /v1/admin/mcp-servers/s1": DETAIL({ report: REPORT({ recommended_verdict: "rejected", findings: [{ check: "capabilities", severity: "high", message: "x" }] }) }),
      "POST /v1/admin/mcp-servers/s1/approve": json(DETAIL({ verdict: "approved" })) }));
    ui("/mcp/s1");
    const approve = await screen.findByRole("button", { name: "Approve server" });
    expect(approve).toBeDisabled();
    await userEvent.click(screen.getByLabelText(/still want to approve/));
    await userEvent.click(approve);
    expect(await screen.findByText("Server approved")).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith("/approve"))!.body).toEqual({ allowed_tools: null, acknowledge_findings: true });
  });

  it("approving with fewer tools sends the allowed list", async () => {
    const { calls } = mockApi(base({ "POST /v1/admin/mcp-servers/s1/approve": json(DETAIL({ verdict: "approved_with_limits" })) }));
    ui("/mcp/s1");
    await userEvent.click(await screen.findByLabelText("Allow send_email"));
    const go = screen.getByRole("button", { name: "Approve with limits (1 of 2 tools)" });
    await userEvent.click(go);
    await waitFor(() => expect(calls.find((c) => c.path.endsWith("/approve"))!.body).toEqual({ allowed_tools: ["read_email"], acknowledge_findings: false }));
  });

  it("checking for changes reports drift as a warning", async () => {
    mockApi(base({ "GET /v1/admin/mcp-servers/s1": DETAIL({ verdict: "approved", approved_fingerprint: "ab".repeat(32) }), "POST /v1/admin/mcp-servers/s1/check": json({ status: "drifted", verdict: "suspended" }) }));
    ui("/mcp/s1");
    await userEvent.click(await screen.findByRole("button", { name: "Check for changes" }));
    expect(await screen.findByText("The server changed and is now suspended")).toBeInTheDocument();
  });

  it("a suspended server explains what to do", async () => {
    mockApi(base({ "GET /v1/admin/mcp-servers/s1": DETAIL({ verdict: "suspended" }) }));
    ui("/mcp/s1");
    expect(await screen.findByRole("alert")).toHaveTextContent("changed after it was approved");
  });

  it("removal needs the server name typed", async () => {
    const { calls } = mockApi(base({ "DELETE /v1/admin/mcp-servers/s1": new Response(null, { status: 204 }) }));
    ui("/mcp/s1");
    await userEvent.click(await screen.findByRole("button", { name: "Remove server" }));
    const dlg = screen.getAllByRole("dialog").at(-1)!;
    const go = within(dlg).getByRole("button", { name: "Remove server" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(/Type/), "mail");
    await userEvent.click(go);
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });

  it("analysts can scan but not approve; viewers can only read", async () => {
    mockApi(base({ "GET /v1/auth/me": json({ ...ME, role: "analyst" }) }));
    ui("/mcp/s1");
    expect(await screen.findByRole("button", { name: "Scan again" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve server" })).toBeNull();
  });

  it("viewers see the report and no buttons", async () => {
    mockApi(base({ "GET /v1/auth/me": json({ ...ME, role: "viewer" }) }));
    ui("/mcp/s1");
    await screen.findByRole("heading", { name: "MCP server mail" });
    for (const n of ["Scan again", "Approve server", "Reject server", "Check for changes"]) expect(screen.queryByRole("button", { name: n })).toBeNull();
  });
});
