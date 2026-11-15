import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
const configDirectory = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  testDir: configDirectory,
  testIgnore: ["**/authenticated.spec.ts"],
  timeout: 30000,
  use: { baseURL: "http://127.0.0.1:5173", trace: "on-first-retry" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["iPhone 13"], browserName: "chromium" } }
  ],
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5173",
    cwd: path.resolve(configDirectory, "../../src/frontend"),
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 120000
  }
});
