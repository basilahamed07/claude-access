import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { slugError } from "./ConnectAgentFlow";
import AgentsPage from "./AgentsPage";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const AGENT = { id: "a1", slug: "email-reader-01", name: "Email reader", owner: "ops", purpose: "", risk_tier: "medium", mode: "enforce", key_mode: "stored",
  status: "active", created_at: "2026-10-26T10:00:00Z", updated_at: "2026-10-26T10:00:00Z", key_count: 1, active_policy_version: 3, last_seen_at: null, upstream_id: null };
const KEY = { id: "k1", key: "ask_live_abcdefghijklmnopqrstuvwx", prefix: "ask_live_abcd1234", created_at: "2026-10-26T10:00:00Z" };
const SNIPPET = (lang: string) => ({ lang, code: `client(api_key="ask_live_...") # ${lang}` });

describe("slug rules mirror the API", () => {
  it.each([["ok-agent", null], ["a", "Use at least 2 characters."], ["Bad", "Use lowercase letters, numbers and hyphens, starting with a letter or number."],
    ["-x", "Use lowercase letters, numbers and hyphens, starting with a letter or number."], ["", null]])("%s", (slug, msg) => expect(slugError(slug)).toBe(msg));
});

describe("agents", () => {
  it("lists agents with status, mode, policy and last seen", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [AGENT, { ...AGENT, id: "a2", slug: "pay-bot", name: "Pay bot", mode: "monitor", active_policy_version: null }] }, "GET /v1/admin/approvals": { items: [] } });
    renderApp(<AgentsPage />);
    expect(await screen.findByText("Email reader")).toBeInTheDocument();
    expect(screen.getByText("v3")).toBeInTheDocument();
    expect(screen.getByText("Monitor only")).toBeInTheDocument();
    expect(screen.getByText("None (default deny)")).toBeInTheDocument();
    expect(screen.getAllByText("Never")).toHaveLength(2);
  });

  it("empty state tells you the next step", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [] } });
    renderApp(<AgentsPage />);
    expect(await screen.findByText("No agents yet")).toBeInTheDocument();
    expect(screen.getByText("Connect an agent to see its first request here.")).toBeInTheDocument();
  });

  it("connect flow: create, key shown once, snippets with the real key, first request arrives", async () => {
    let events: unknown[] = [];
    const { calls } = mockApi({
      "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [] }, "GET /v1/admin/upstreams": [{ id: "u1", name: "openai-main" }],
      "POST /v1/admin/agents": json(AGENT, { status: 201 }), "POST /v1/admin/agents/email-reader-01/keys": json(KEY, { status: 201 }),
      "GET /v1/admin/agents/email-reader-01/snippet": (url) => json(SNIPPET(url.searchParams.get("lang")!)),
      "GET /v1/admin/events": () => json({ items: events }),
    });
    renderApp(<AgentsPage />);
    await userEvent.click((await screen.findAllByRole("button", { name: "Connect agent" }))[0]);
    const create = screen.getByRole("button", { name: "Create agent" });
    expect(create).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Agent id"), "Email Reader");
    expect(screen.getByText(/Use lowercase letters/)).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("Agent id"));
    await userEvent.type(screen.getByLabelText("Agent id"), "email-reader-01");
    await userEvent.type(screen.getByLabelText("Name"), "Email reader");
    await userEvent.type(screen.getByLabelText("Owner"), "ops@acme.com");
    await userEvent.selectOptions(screen.getByLabelText("Model provider"), "u1");
    await userEvent.click(create);
    expect(await screen.findByText(/shown once/)).toBeInTheDocument();
    expect((screen.getByLabelText("API key") as HTMLInputElement).value).toBe(KEY.key);
    expect(calls.find((c) => c.path === "/v1/admin/agents" && c.method === "POST")!.body).toMatchObject({ slug: "email-reader-01", upstream_id: "u1" });
    await userEvent.click(screen.getByRole("button", { name: "I have copied the key" }));
    expect(await screen.findByText(/client\(api_key="ask_live_abcdefghijklmnopqrstuvwx"\) # python-openai/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "curl" }));
    expect(await screen.findByText(/# curl/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Send a test request" }));
    expect(await screen.findByText(/Waiting for the first request/)).toBeInTheDocument();
    events = [{ type: "request.received", ts: "2026-10-26T10:05:00Z" }];
    expect(await screen.findByText(/First request received/, {}, { timeout: 4000 })).toBeInTheDocument();
  });

  it("shows the API's message when the agent id is taken", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [] }, "GET /v1/admin/upstreams": [], "POST /v1/admin/agents": problem(409, "conflict", "Agent 'dup-agent' already exists") });
    renderApp(<AgentsPage />);
    await userEvent.click((await screen.findAllByRole("button", { name: "Connect agent" }))[0]);
    await userEvent.type(screen.getByLabelText("Agent id"), "dup-agent");
    await userEvent.type(screen.getByLabelText("Name"), "Dup");
    await userEvent.type(screen.getByLabelText("Owner"), "me");
    await userEvent.click(screen.getByRole("button", { name: "Create agent" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Agent 'dup-agent' already exists");
  });

  it("keys are masked; revoke needs typing, rotate asks for overlap and shows the new key once", async () => {
    let keys = [{ id: "k1", prefix: "ask_live_abcd1234", created_at: "2026-10-26T10:00:00Z", expires_at: null, revoked_at: null }];
    const { calls } = mockApi({
      "GET /v1/auth/me": json(ME), "GET /v1/admin/agents": { items: [AGENT] }, "GET /v1/admin/agents/email-reader-01/keys": () => json(keys),
      "POST /v1/admin/agents/email-reader-01/keys/k1/rotate": json({ ...KEY, id: "k2", key: "ask_live_NEWNEWNEWNEWNEWNEWNEWNEWNEW" }, { status: 201 }),
      "POST /v1/admin/agents/email-reader-01/keys/k1/revoke": () => { keys = [{ ...keys[0], revoked_at: "2026-10-26T11:00:00Z" } as never]; return json(keys[0]); },
      "GET /v1/admin/agents/email-reader-01/snippet": json(SNIPPET("python-openai")),
    });
    renderApp(<AgentsPage />);
    await userEvent.click(await screen.findByRole("row", { name: "Manage keys for Email reader" }));
    expect(await screen.findByText("ask_live_abcd1234…")).toBeInTheDocument();
    expect(screen.queryByText(KEY.key)).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "Rotate key" }));
    expect((screen.getByLabelText(/Old key keeps working/) as HTMLInputElement).value).toBe("24");
    await userEvent.click(within(screen.getByRole("dialog", { name: "Rotate this key" })).getByRole("button", { name: "Rotate key" }));
    expect(await screen.findByText("Key rotated")).toBeInTheDocument();
    expect((await screen.findByLabelText("New API key") as HTMLInputElement).value).toContain("NEWNEW");
    expect(calls.find((c) => c.path.endsWith("/rotate"))!.body).toEqual({ overlap_seconds: 86400 });

    await userEvent.click(screen.getByRole("button", { name: "Revoke key" }));
    const dialogs = screen.getAllByRole("dialog");
    const typed = dialogs[dialogs.length - 1];
    const go = within(typed).getByRole("button", { name: "Revoke key" });
    expect(go).toBeDisabled();
    await userEvent.type(within(typed).getByLabelText(/Type/), "revoke");
    await userEvent.click(go);
    expect(await screen.findByText("Key revoked")).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/revoke"))).toBe(true));
  });

  it("viewers see the list but no connect button", async () => {
    mockApi({ "GET /v1/auth/me": json({ ...ME, role: "viewer" }), "GET /v1/admin/agents": { items: [AGENT] } });
    renderApp(<AgentsPage />);
    await screen.findByText("Email reader");
    expect(screen.queryByRole("button", { name: "Connect agent" })).toBeNull();
  });
});
