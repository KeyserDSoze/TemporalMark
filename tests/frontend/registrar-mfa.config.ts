import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

// CI-only registrar browser password+real TOTP; no screenshots or traces that
// could retain OTP seed, authorization code, or short-lived bearer tokens.
export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: "registrar-mfa.spec.ts",
  workers: 1,
  retries: 0,
  timeout: 90000,
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:8081",
    trace: "off", screenshot: "off", video: "off"
  }
});
