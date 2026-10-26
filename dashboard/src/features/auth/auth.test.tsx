import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Route, Routes } from "react-router-dom";
import { AppRoutes } from "../../app/router";
import { ME, mockApi, problem, renderApp, json } from "../../test/helpers";

const pages = { "GET /v1/admin/stats/overview": {}, "GET /v1/admin/approvals": { items: [] }, "GET /v1/admin/approvals/abc": problem(404, "not_found", "Approval not found") };

describe("auth shell", () => {
  it("sends a signed-out visitor to login and returns to the same page after sign in", async () => {
    let signedIn = false;
    const { calls } = mockApi({
      "GET /v1/auth/me": () => (signedIn ? json(ME) : problem(401, "unauthenticated", "Sign in")),
      "POST /v1/auth/login": () => { signedIn = true; return json({ user_id: "u1", tenant_id: "t1", role: "admin", csrf_token: "csrf-1" }); },
      ...pages,
    });
    renderApp(<AppRoutes />, { path: "/approvals/abc" });
    expect(await screen.findByRole("heading", { name: "Sign in to AgentShield" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Email"), "ana@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Approvals", hidden: true })).toBeInTheDocument();
    expect(await screen.findByText("Approval not found")).toBeInTheDocument();     // back on the approval we were opening
    expect(calls.find((c) => c.path === "/v1/auth/login")!.body).toEqual({ email: "ana@acme.com", password: "correct-horse-battery" });
  });

  it("shows a plain message for a wrong password", async () => {
    mockApi({ "GET /v1/auth/me": problem(401, "unauthenticated", "Sign in"), "POST /v1/auth/login": problem(401, "unauthenticated", "Invalid credentials") });
    renderApp(<AppRoutes />, { path: "/login" });
    await userEvent.type(await screen.findByLabelText("Email"), "a@b.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrongwrongwrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Email or password is wrong. Check both and try again.");
  });

  it("a 401 in the middle of a session goes back to login with the return path", async () => {
    let expired = false;
    mockApi({
      "GET /v1/auth/me": () => (expired ? problem(401, "unauthenticated", "x") : json(ME)),
      "GET /v1/admin/approvals": () => { expired = true; return problem(401, "unauthenticated", "Session expired"); },
    });
    renderApp(<AppRoutes />, { path: "/sessions" });
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in to AgentShield" })).toBeInTheDocument());
  });

  it("hides the Approvals link from viewers", async () => {
    mockApi({ "GET /v1/auth/me": json({ ...ME, role: "viewer" }) });
    renderApp(<AppRoutes />, { path: "/" });
    await screen.findByRole("link", { name: "Overview" });
    expect(screen.queryByRole("link", { name: /Approvals/ })).toBeNull();
  });

  it("shows the pending approvals count in the rail", async () => {
    mockApi({ "GET /v1/auth/me": json(ME), "GET /v1/admin/approvals": { items: [{ id: "1" }, { id: "2" }] } });
    renderApp(<AppRoutes />, { path: "/" });
    expect(await screen.findByLabelText("2 pending")).toBeInTheDocument();
  });
});
void Route; void Routes;

describe("sign up", () => {
  const fill = async (pw = "a-long-passphrase-1") => {
    await userEvent.type(await screen.findByLabelText("Workspace name"), "Acme");
    await userEvent.type(screen.getByLabelText("Your email"), "ana@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), pw);
  };

  it("creates the workspace, signs in and lands on Agents", async () => {
    let signedIn = false;
    const { calls } = mockApi({
      "GET /v1/auth/me": () => (signedIn ? json(ME) : problem(401, "unauthenticated", "Sign in")),
      "POST /v1/signup": json({ tenant_id: "t1", slug: "acme" }, { status: 201 }),
      "POST /v1/auth/login": () => { signedIn = true; return json({ user_id: "u1", tenant_id: "t1", role: "admin", csrf_token: "c" }); },
      "GET /v1/admin/agents": { items: [] }, "GET /v1/admin/approvals": { items: [] },
    });
    renderApp(<AppRoutes />, { path: "/signup" });
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(await screen.findByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(calls.find((c) => c.path === "/v1/signup")!.body).toEqual({ tenant_name: "Acme", email: "ana@acme.com", password: "a-long-passphrase-1" });
  });

  it("explains a short password and keeps the button off", async () => {
    mockApi({ "GET /v1/auth/me": problem(401, "unauthenticated", "x") });
    renderApp(<AppRoutes />, { path: "/signup" });
    await fill("short");
    expect(screen.getByText("Use at least 12 characters (5 so far).")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create workspace" })).toBeDisabled();
  });

  it.each([[403, "forbidden", "Sign-up is turned off on this installation. Ask an administrator to add you."],
    [409, "conflict", "That workspace name or e-mail is already registered"]])("shows the reason when the API says %s", async (status, code, expected) => {
    mockApi({ "GET /v1/auth/me": problem(401, "unauthenticated", "x"), "POST /v1/signup": problem(status, code, "That workspace name or e-mail is already registered") });
    renderApp(<AppRoutes />, { path: "/signup" });
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(expected);
  });

  it("is linked from the login page", async () => {
    mockApi({ "GET /v1/auth/me": problem(401, "unauthenticated", "x") });
    renderApp(<AppRoutes />, { path: "/login" });
    expect(await screen.findByRole("link", { name: "Create a workspace" })).toHaveAttribute("href", "/signup");
  });
});
