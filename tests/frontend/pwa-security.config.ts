import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: "pwa-navigation-security.spec.ts",
  timeout: 60000,
  use: {
    baseURL: "http://127.0.0.1:3000",
    serviceWorkers: "allow",
    trace: "retain-on-failure"
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }]
});
