// Disposable CI ONLY: separate registrar password+real TOTP, Code+PKCE S256.
// No passwords/OTP seeds/auth codes/tokens in CI output, screenshots or traces.
import { test, expect } from "@playwright/test";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { writeFileSync } from "node:fs";
import { jwtVerify, createRemoteJWKSet } from "jose";

const issuer = "http://localhost:8081/realms/temporalmark-mfa-ci";
const redirect = "http://127.0.0.1:45679/registrar-mfa-callback";
const clientId = "temporalmark-registrar-pkce-ci";
const username = "demo-mfa-registrar";
const password = "disposable-registrar-otp-password";
const audience = "temporalmark-credential-registrar";
const requiredAcr = "urn:temporalmark:loa:2";
const subject = "00000000-0000-0000-0000-000000000035";

function totp(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0;
  const data: number[] = [];
  for (const ch of secret.replace(/\s/g, "").replace(/=+$/, "").toUpperCase()) {
    const digit = alphabet.indexOf(ch);
    if (digit < 0) throw new Error("Invalid disposable OTP encoding");
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      data.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", Buffer.from(data)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

test("registrar requires fresh real password+TOTP browser login and independent signed audience", async ({ browser }) => {
  let callbackServer: Server | undefined;
  const callbacks: { code: string; state: string }[] = [];
  try {
    callbackServer = createServer((request, response) => {
      // Do not log the callback URL: it contains a short-lived authorization code.
      const received = new URL(request.url ?? "/", redirect);
      if (received.pathname === "/registrar-mfa-callback" && received.searchParams.has("code")) {
        callbacks.push({
          code: received.searchParams.get("code")!,
          state: received.searchParams.get("state")!
        });
      }
      response.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
      response.end("CI registrar OIDC callback received");
    });
    await new Promise<void>((resolve, reject) => {
      callbackServer!.once("error", reject);
      callbackServer!.listen(45679, "127.0.0.1", resolve);
    });

    async function start() {
      const context = await browser.newContext({ recordVideo: undefined });
      const page = await context.newPage();
      const verifier = randomBytes(48).toString("base64url");
      const state = randomBytes(18).toString("base64url");
      const nonce = randomBytes(18).toString("base64url");
      const url = new URL(issuer + "/protocol/openid-connect/auth");
      for (const [key, value] of Object.entries({
        client_id: clientId, response_type: "code", scope: "openid",
        redirect_uri: redirect,
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256", state, nonce, acr_values: requiredAcr,
        prompt: "login", max_age: "0",
        claims: JSON.stringify({ id_token: { acr: { essential: true, values: [requiredAcr] } } })
      })) url.searchParams.set(key, value);
      await page.goto(url.toString());
      await expect(page.locator("#username")).toBeVisible();
      await page.locator("#username").fill(username);
      await page.locator("#password").fill(password);
      await page.locator("#kc-login").click();
      return { context, page, verifier, state };
    }

    // OTP credential setup is NOT a completed MFA login.
    const first = await start();
    await expect(first.page.locator("#kc-totp-settings-form")).toBeVisible();
    expect(callbacks).toHaveLength(0);
    await first.page.locator("#mode-manual").click();
    const seed = (await first.page.locator("#kc-totp-secret-key").innerText()).trim();
    expect(seed.length).toBeGreaterThan(12);
    const usedPeriod = Math.floor(Date.now() / 30000);
    await first.page.locator("#totp").fill(totp(seed));
    await first.page.locator("#saveTOTPBtn").click();
    await expect.poll(() => callbacks.length, { timeout: 20000 }).toBe(1);
    callbacks.length = 0; // Never exchange enrollment authorization code.
    await first.context.close();

    await expect.poll(() => Math.floor(Date.now() / 30000), {
      timeout: 35000, intervals: [300, 700, 1000]
    }).toBeGreaterThan(usedPeriod);

    const second = await start();
    await expect(second.page.locator("#otp")).toBeVisible({ timeout: 20000 });
    expect(callbacks).toHaveLength(0);
    const valid = totp(seed);
    await second.page.locator("#otp").fill(valid === "000000" ? "111111" : "000000");
    await second.page.locator("#kc-login").click();
    await expect(second.page.locator("#otp")).toBeVisible();
    expect(callbacks).toHaveLength(0);

    await second.page.locator("#otp").fill(totp(seed));
    await second.page.locator("#kc-login").click();
    await expect.poll(() => callbacks.length, { timeout: 20000 }).toBe(1);
    const authorization = callbacks.pop()!;
    expect(authorization.state).toBe(second.state);

    const exchange = await fetch(issuer + "/protocol/openid-connect/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId, grant_type: "authorization_code",
        redirect_uri: redirect, code: authorization.code,
        code_verifier: second.verifier
      })
    });
    expect(exchange.status).toBe(200);
    const json = await exchange.json() as { access_token: string };
    expect(typeof json.access_token).toBe("string");

    const discovery = await fetch(issuer + "/.well-known/openid-configuration");
    expect(discovery.ok).toBe(true);
    const jwksUrl = (await discovery.json() as { jwks_uri: string }).jwks_uri;
    const { payload } = await jwtVerify(json.access_token, createRemoteJWKSet(new URL(jwksUrl)), {
      issuer, audience, algorithms: ["RS256", "PS256", "ES256"]
    });
    expect(payload.sub).toBe(subject);
    expect(payload.role).toContain("platform_credential_registrar");
    expect(payload.acr).toBe(requiredAcr);
    expect(typeof payload.auth_time).toBe("number");
    expect(typeof payload.iat).toBe("number");
    const now = Math.floor(Date.now() / 1000);
    expect(payload.auth_time as number).toBeGreaterThanOrEqual(now - 120);
    expect(payload.auth_time as number).toBeLessThanOrEqual((payload.iat as number) + 30);

    const file = process.env.TEMPORALMARK_CI_REGISTRAR_TOKEN_FILE;
    if (file) writeFileSync(file, json.access_token, { mode: 0o600, flag: "wx" });
    await second.context.close();
  } finally {
    await new Promise<void>(resolve => callbackServer?.close(() => resolve()) ?? resolve());
  }
});
