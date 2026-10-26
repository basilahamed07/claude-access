import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill("demo@example.com");
  await page.getByLabel("Password").fill("demo-password-123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
}

const PAGES = ["/", "/sessions", "/approvals", "/agents", "/policies", "/mcp", "/alerts", "/settings"];

for (const scheme of ["light", "dark"] as const) {
  test(`no serious or critical accessibility violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/login");
    let results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(results.violations.filter((v) => v.impact === "serious" || v.impact === "critical"), "login").toEqual([]);
    await page.goto("/signup");
    results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(results.violations.filter((v) => v.impact === "serious" || v.impact === "critical"), "signup").toEqual([]);
    await login(page);
    for (const path of PAGES) {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
      const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).slice(0, 3).join(" | ")}`), `${path} (${scheme})`).toEqual([]);
    }
  });
}

test("the session tape has no violations either, and works at phone width", async ({ page }) => {
  await login(page);
  await page.goto("/sessions");
  await page.getByRole("row", { name: /Open session for email-reader-01/ }).first().click();
  await expect(page.getByRole("grid", { name: "Session events" })).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag22aa"]).analyze();
  expect(results.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  await page.setViewportSize({ width: 360, height: 740 });
  await expect(page.getByRole("grid", { name: "Session events" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await expect(page.locator(".lane-tag").first()).toBeVisible();
});
