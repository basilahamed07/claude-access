import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import { defineConfig } from "vite";

// A separate build of one read-only page for hosting on any static host: `npm run build:static` -> dist-static/
export default defineConfig({
  plugins: [react()],
  base: "./",
  publicDir: "static",
  build: { outDir: "dist-static", emptyOutDir: true, rollupOptions: { input: { index: resolve(__dirname, "static.html") } } },
});
