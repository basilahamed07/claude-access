import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

// A pre-installed Chromium (CI image / dev container) is used when present; otherwise Playwright's own download.
const CHROMIUM = process.env.CHROMIUM_PATH ?? ["/opt/pw-browsers/chromium"].find((p) => existsSync(p));

const API_PORT = process.env.API_PORT ?? "8000";
const WEB_PORT = process.env.WEB_PORT ?? "5173";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: `http://127.0.0.1:${WEB_PORT}`, trace: "retain-on-failure", ...devices["Desktop Chrome"], launchOptions: CHROMIUM ? { executablePath: CHROMIUM } : {} },
  webServer: [
    { command: "../agentshield/scripts/run_stack.sh", url: `http://127.0.0.1:${API_PORT}/healthz`, timeout: 120_000, reuseExistingServer: !process.env.CI, env: { PORT: API_PORT } },
    { command: `npm run build && npx vite preview --host 127.0.0.1 --port ${WEB_PORT}`, url: `http://127.0.0.1:${WEB_PORT}`, timeout: 120_000, reuseExistingServer: !process.env.CI,
      env: { AGENTSHIELD_API: `http://127.0.0.1:${API_PORT}` } },
  ],
});
