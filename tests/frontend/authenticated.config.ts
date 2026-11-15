import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: "authenticated.spec.ts",
  timeout: 60000,
  use: { baseURL: "http://localhost:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }]
});
