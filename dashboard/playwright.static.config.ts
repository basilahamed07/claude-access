import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

const CHROMIUM = process.env.CHROMIUM_PATH ?? ["/opt/pw-browsers/chromium"].find((p) => existsSync(p));
export default defineConfig({
  testDir: "./e2e-static",
  timeout: 30_000,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: "http://127.0.0.1:5199", ...devices["Desktop Chrome"], launchOptions: CHROMIUM ? { executablePath: CHROMIUM } : {} },
  webServer: { command: "npm run build:static && npx vite preview --config vite.static.config.ts --outDir dist-static --host 127.0.0.1 --port 5199", url: "http://127.0.0.1:5199", reuseExistingServer: !process.env.CI, timeout: 120_000 },
});
