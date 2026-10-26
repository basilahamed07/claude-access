import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("the hosted replay shows the recorded attack, says it is a recording, and calls nothing but its own files", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (r) => requests.push(r.url()));
  await page.goto("/");
  await expect(page.getByText("Recorded demo. No live agent.")).toBeVisible();
  const tape = page.getByRole("grid", { name: "Session events" });
  await expect(tape).toBeVisible();
  await expect(tape.locator(".trow.is-blocked")).not.toHaveCount(0);
  await expect(page.getByText(/Chain verified \(\d+ events\) when this was recorded/)).toBeVisible();
  await tape.focus();
  await page.keyboard.press("Enter");                                   // the cursor starts on the blocked step
  await expect(page.getByRole("dialog").getByText("deny-external-send").first()).toBeVisible();
  const foreign = requests.filter((u) => !u.startsWith("http://127.0.0.1:5199/") && !u.startsWith("data:"));
  const api = requests.filter((u) => u.includes("/v1/"));
  expect(foreign).toEqual([]);
  expect(api).toEqual([]);
});

test("the hosted replay has no serious accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("grid", { name: "Session events" })).toBeVisible();
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag22aa"]).analyze();
  expect(r.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
});
