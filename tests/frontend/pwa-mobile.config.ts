import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: "pwa-mobile-install.spec.ts",
  timeout: 90000,
  use: {
    baseURL: "http://127.0.0.1:3000",
    serviceWorkers: "allow",
    trace: "retain-on-failure"
  },
  projects: [{
    name: "android-chromium-emulated",
    use: { ...devices["Pixel 7"], browserName: "chromium" }
  }]
});
