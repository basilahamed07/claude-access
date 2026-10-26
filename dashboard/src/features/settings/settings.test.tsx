import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import SettingsPage from "./SettingsPage";
import { toModelMap } from "./UpstreamsPanel";
import { ME, json, mockApi, problem, renderApp } from "../../test/helpers";

const UP = { id: "u1", name: "openai-main", kind: "openai", base_url: "https://api.openai.com/v1", has_key: true, model_map: { fast: { model: "gpt-4.1-mini" } }, judge_model: null, created_at: "x" };
const USERS = { items: [{ id: "u1", email: "ana@acme.com", role: "admin", created_at: "x", disabled_at: null }, { id: "u2", email: "bo@acme.com", role: "viewer", created_at: "x", disabled_at: null }] };
const SETTINGS = { on_malicious: "sanitize", mark_untrusted: true, webhook_url: null, judge_upstream_id: null, retention: { payload_days: 30, envelope_days: 180, incident_days: 1095 } };
const base = (extra: Record<string, unknown> = {}) => ({ "GET /v1/auth/me": json(ME), "GET /v1/admin/upstreams": [UP], "GET /v1/admin/users": USERS,
  "GET /v1/admin/settings": json(SETTINGS, { headers: { etag: '"s1"' } }), ...extra });

describe("settings", () => {
  it("is for admins only", async () => {
    mockApi({ "GET /v1/auth/me": json({ ...ME, role: "analyst" }) });
    renderApp(<SettingsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Settings need the admin role.");
  });

  it("price rows convert dollars per million tokens to micro-dollars and skip empty rows", () => {
    expect(toModelMap([{ alias: "fast", model: "gpt-4.1-mini", inUsd: "0.4", outUsd: "1.6" }, { alias: "", model: "", inUsd: "", outUsd: "" }]))
      .toEqual({ fast: { model: "gpt-4.1-mini", input_micro_usd_per_mtok: 400000, output_micro_usd_per_mtok: 1600000 } });
  });

  it("an upstream's API key is write-only: 'Key saved' is shown, never the value", async () => {
    const { calls } = mockApi(base({ "PATCH /v1/admin/upstreams/u1": json(UP) }));
    renderApp(<SettingsPage />);
    expect(await screen.findByText("Key saved")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/sk-/);
    await userEvent.click(screen.getByRole("button", { name: "Replace key" }));
    const input = screen.getByLabelText("New API key") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.value).toBe("");
    await userEvent.type(input, "sk-new-secret");
    await userEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("Key saved", { selector: ".toast" })).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ api_key: "sk-new-secret" });
  });

  it("adds a provider with prices and shows the server's validation error", async () => {
    const { calls } = mockApi(base({ "POST /v1/admin/upstreams": problem(422, "validation_failed", "base_url rejected: private address") }));
    renderApp(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Add provider" }));
    const dlg = screen.getByRole("dialog", { name: "Add provider" });
    await userEvent.type(within(dlg).getByLabelText("Name"), "local");
    await userEvent.clear(within(dlg).getByLabelText("Base URL"));
    await userEvent.type(within(dlg).getByLabelText("Base URL"), "http://10.0.0.5/v1");
    await userEvent.type(within(dlg).getByLabelText("Alias 1"), "fast");
    await userEvent.type(within(dlg).getByLabelText("Model 1"), "llama");
    await userEvent.type(within(dlg).getByLabelText("Input price per million tokens 1"), "0.5");
    await userEvent.click(within(dlg).getByRole("button", { name: "Add provider" }));
    expect(await within(dlg).findByRole("alert")).toHaveTextContent("base_url rejected: private address");
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ name: "local", api_key: null, model_map: { fast: { model: "llama", input_micro_usd_per_mtok: 500000 } } });
  });

  it("tests a connection and reports the result", async () => {
    mockApi(base({ "POST /v1/admin/upstreams/u1/test": json({ ok: true, status: 200, latency_ms: 120 }) }));
    renderApp(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("Connection works (120 ms)")).toBeInTheDocument();
  });

  it("removing a provider needs its name typed", async () => {
    const { calls } = mockApi(base({ "DELETE /v1/admin/upstreams/u1": new Response(null, { status: 204 }) }));
    renderApp(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove provider" }));
    const dlg = screen.getByRole("dialog");
    const go = within(dlg).getByRole("button", { name: "Remove provider" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(/Type/), "openai-main");
    await userEvent.click(go);
    expect(await screen.findByText("Provider removed")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("changes a role and adds a user", async () => {
    const { calls } = mockApi(base({ "PATCH /v1/admin/users/u2": json(USERS.items[1]), "POST /v1/admin/users": json(USERS.items[1], { status: 201 }) }));
    renderApp(<SettingsPage />);
    await userEvent.selectOptions(await screen.findByLabelText("Role for bo@acme.com"), "analyst");
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ role: "analyst" }));
    await userEvent.type(screen.getByLabelText("Email"), "new@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), "twelve-chars-ok");
    await userEvent.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByText("User added")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ email: "new@acme.com", password: "twelve-chars-ok", role: "viewer" });
  });

  it("retention cannot go below the floors", async () => {
    mockApi(base());
    renderApp(<SettingsPage />);
    const env = await screen.findByLabelText("Audit envelopes");
    await userEvent.clear(env);
    await userEvent.type(env, "90");
    expect(screen.getByText("Cannot be below 180 days.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save settings" })).toBeDisabled();
  });

  it("saves protection settings with the ETag and surfaces the webhook validation error", async () => {
    const { calls } = mockApi(base({ "PATCH /v1/admin/settings": problem(422, "validation_failed", "webhook_url rejected: private address") }));
    renderApp(<SettingsPage />);
    await userEvent.selectOptions(await screen.findByLabelText("When an attack is found in content"), "quarantine");
    await userEvent.type(screen.getByLabelText("Approval webhook URL"), "http://169.254.169.254/x");
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("webhook_url rejected: private address");
    const call = calls.find((c) => c.method === "PATCH")!;
    expect(call.headers["If-Match"]).toBe('"s1"');
    expect(call.body).toMatchObject({ on_malicious: "quarantine", webhook_url: "http://169.254.169.254/x" });
  });
});
