/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const API = process.env.AGENTSHIELD_API ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/v1": API, "/healthz": API } },
  preview: { port: 5173, proxy: { "/v1": API, "/healthz": API } },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"], css: false, exclude: ["e2e/**", "e2e-static/**", "node_modules/**"] },
});
