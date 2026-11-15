import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Security: no browser traces, videos or screenshots that could retain OTP
// seeds, passwords, authorization codes, token URLs or secret inputs.
export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: "mfa.spec.ts",
  workers: 1,
  retries: 0,
  timeout: 90000,
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:8081",
    trace: "off", screenshot: "off", video: "off"
  }
});
