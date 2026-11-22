import { defineConfig } from "@playwright/test";

// Runs against a built site and a running API: `npm run build && npx wrangler dev` plus the FastAPI app.
export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  use: { baseURL: process.env.SITE_URL || "http://127.0.0.1:8787", viewport: { width: 1440, height: 900 } },
  reporter: [["list"]],
});
