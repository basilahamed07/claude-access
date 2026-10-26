import { expect, test, type Page } from "@playwright/test";

const EMAIL = "demo@example.com";
const PASSWORD = "demo-password-123";

async function login(page: Page, next = "/") {
  await page.goto(next);
  await expect(page.getByRole("heading", { name: "Sign in to AgentShield" })).toBeVisible();
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("wrong password is explained, right password signs in and returns to the page you wanted", async ({ page }) => {
  await page.goto("/sessions");
  await expect(page).toHaveURL(/\/login\?next=%2Fsessions/);
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Email or password is wrong");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Sessions", level: 1 })).toBeVisible();
});

test("from the alert to the blocked step, and a relaxed policy shows the ghost mark", async ({ page }) => {
  await login(page, "/alerts");
  // 1. the attack raised alerts
  const alerts = page.getByRole("region", { name: "Alerts" });
  await expect(alerts.getByText("Action blocked")).toBeVisible();
  await expect(alerts.getByText("Attack found in content")).toBeVisible();

  // 2. open the tape from the block alert
  await alerts.getByRole("row", { name: /Action blocked/ }).getByRole("link", { name: "Open the tape" }).click();
  const tape = page.getByRole("grid", { name: "Session events" });
  await expect(tape).toBeVisible();
  await expect(page.getByText(/Chain verified/)).toBeVisible();
  await expect(tape.getByText("Blocked").first()).toBeVisible();
  await expect(tape.locator(".trow.is-blocked")).not.toHaveCount(0);

  // 3. step to the blocking decision with the keyboard and read the recorded payload
  const block = tape.locator(".trow.is-blocked", { hasText: "deny-external-send" }).first();
  await block.scrollIntoViewIfNeeded();
  await block.click();
  await page.keyboard.press("Enter");
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("deny-external-send").first()).toBeVisible();
  await expect(drawer.getByText("Recorded payload")).toBeVisible();
  await page.keyboard.press("Escape");

  // 4. save a relaxed policy and re-check the session against it
  const csrf = (await (await page.request.get("/v1/auth/me")).json()).csrf_token as string;
  const current = await (await page.request.get("/v1/admin/agents/email-reader-01/policy/versions/1")).json();
  const relaxed = (current.yaml as string).replace(/  - id: deny-external-send[\s\S]*?(?=  - id: allow-internal-send)/, "  - id: allow-any-send\n    effect: allow\n    tool: send_email\n");
  const saved = await page.request.post("/v1/admin/agents/email-reader-01/policy/versions", { headers: { "X-CSRF-Token": csrf }, data: { yaml: relaxed } });
  expect(saved.status()).toBe(201);
  const version = (await saved.json()).version as number;

  await page.reload();                                             // the version list is read when the tape opens
  await expect(tape).toBeVisible();
  await page.getByLabel("Re-check with policy").selectOption(String(version));
  await page.getByRole("button", { name: "Re-check" }).click();
  await expect(page.getByText(`1 decision would change under v${version}.`)).toBeVisible();
  const ghost = tape.locator(".ghost");
  await expect(ghost).toHaveCount(1);
  await expect(ghost).toContainText("Cleared");

  // 5. mark it as an incident
  await page.getByRole("button", { name: "Mark as incident" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Mark as incident" }).click();
  await expect(page.getByText("Incident created")).toBeVisible();
});

test("the overview leads with what needs you, and the chart has a table view", async ({ page }) => {
  await login(page, "/");
  await expect(page.getByRole("heading", { name: "Needs you" })).toBeVisible();
  await expect(page.getByText("1 action is waiting for an approval")).toBeVisible();
  await page.getByRole("button", { name: "View as table" }).click();
  await expect(page.getByRole("region", { name: "Decisions per hour as a table" })).toBeVisible();
});

test("an analyst can clear a held payment, and the queue empties", async ({ page }) => {
  await login(page, "/approvals");
  await page.getByRole("row", { name: /Review pay_invoice/ }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("Initech")).toBeVisible();
  await expect(drawer.getByText("ask-large-payment")).toBeVisible();
  await drawer.getByLabel("Note (optional)").fill("Matches PO 4411");
  await drawer.getByRole("button", { name: "Approve" }).click();
  await expect(page.locator(".toast", { hasText: "Approved" })).toBeVisible();
  await expect(page.getByText("Nothing is waiting for you")).toBeVisible();
});

test("connect a new agent: the key is shown once and the snippet contains it", async ({ page }) => {
  await login(page, "/agents");
  await page.getByRole("button", { name: "Connect agent" }).first().click();
  await page.getByLabel("Agent id").fill("e2e-agent");
  await page.getByLabel("Name").fill("E2E agent");
  await page.getByLabel("Owner").fill("qa@example.com");
  await page.getByRole("button", { name: "Create agent" }).click();
  await expect(page.getByText(/shown once/)).toBeVisible();
  const key = await page.getByLabel("API key").inputValue();
  expect(key).toMatch(/^ask_live_/);
  await page.getByRole("button", { name: "I have copied the key" }).click();
  await expect(page.getByRole("tabpanel")).toContainText(key);
  await page.getByRole("button", { name: "Done" }).click();
  await page.getByRole("row", { name: /Manage keys for E2E agent/ }).click();
  await expect(page.getByText(`${key.slice(0, 16)}…`)).toBeVisible();
  await expect(page.getByText(key)).toHaveCount(0);
});
