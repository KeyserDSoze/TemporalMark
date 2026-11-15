// Disposable Keycloak development CI realm only. No production secrets, tokens,
// authorization codes, OTP seeds or passwords may be printed or attached.
// A newly registered OTP is NOT counted as MFA authentication: a fresh browser
// session MUST subsequently verify a real TOTP code.
import { test, expect } from "@playwright/test";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { writeFileSync } from "node:fs";
import { jwtVerify, createRemoteJWKSet } from "jose";

const issuer = "http://localhost:8081/realms/temporalmark-mfa-ci";
const redirect = "http://127.0.0.1:45678/oidc-mfa-callback";
const clientId = "temporalmark-mfa-pkce-ci";
const expectedAcr = "urn:temporalmark:loa:2";
const username = "demo-mfa-approver";
const password = "disposable-mfa-password-only";
const expectedSubject = "00000000-0000-0000-0000-000000000034";
const codeChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

function totp(secret: string): string {
  // Keycloak test realm explicitly uses RFC 6238 TOTP: SHA1, six digits, 30s.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.replace(/\s/g, "").replace(/=+$/, "").toUpperCase();
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const digit = alphabet.indexOf(ch);
    if (digit < 0) throw new Error("Invalid disposable Keycloak OTP seed encoding");
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

test("real Keycloak browser password+TOTP, Code+PKCE S256 and verified ACR (not password grant)", async ({ browser }) => {
  let callbackServer: Server | undefined;
  const callbackCodes: { code: string; state: string }[] = [];
  try {
    callbackServer = createServer((request, response) => {
      // Never log full callback URL: it includes a short-lived authorization code.
      const received = new URL(request.url ?? "/", redirect);
      if (received.pathname === "/oidc-mfa-callback" && received.searchParams.has("code")) {
        callbackCodes.push({
          code: received.searchParams.get("code")!,
          state: received.searchParams.get("state")!
        });
      }
      response.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
      response.end("CI OIDC callback captured");
    });
    await new Promise<void>((resolve, reject) => {
      callbackServer!.once("error", reject);
      callbackServer!.listen(45678, "127.0.0.1", resolve);
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
        redirect_uri: redirect, code_challenge: codeChallenge(verifier),
        code_challenge_method: "S256", state, nonce,
        acr_values: expectedAcr, prompt: "login", max_age: "0"
      })) url.searchParams.set(key, value);
      await page.goto(url.toString());
      await expect(page.locator("#username")).toBeVisible();
      await page.locator("#username").fill(username);
      await page.locator("#password").fill(password);
      await page.locator("#kc-login").click();
      return { context, page, verifier, state };
    }

    // First session: Keycloak may require OTP enrollment. Password alone
    // cannot yield a token, but successful enrollment also does NOT prove MFA.
    const enrollment = await start();
    await expect(enrollment.page.locator("#kc-totp-settings-form")).toBeVisible();
    expect(callbackCodes).toHaveLength(0);
    await enrollment.page.locator("#mode-manual").click();
    const seed = (await enrollment.page.locator("#kc-totp-secret-key").innerText()).trim();
    expect(seed.length).toBeGreaterThan(12);
    const enrollmentTimeSlot = Math.floor(Date.now() / 30000);
    await enrollment.page.locator("#totp").fill(totp(seed));
    await enrollment.page.locator("#saveTOTPBtn").click();
    await expect.poll(() => callbackCodes.length, { timeout: 20000 }).toBe(1);
    // Discard the enrollment-session code entirely (no token issuance here).
    callbackCodes.length = 0;
    await enrollment.context.close();

    // Keycloak's default one-time-use policy rejects a TOTP value that was
    // already consumed by the credential-setup ceremony. Do NOT disable
    // the replay protection; wait for the next 30-second RFC6238 counter.
    await expect.poll(() => Math.floor(Date.now() / 30000), {
      timeout: 35000, intervals: [300, 700, 1000]
    }).toBeGreaterThan(enrollmentTimeSlot);

    // Second clean browser: password alone must lead to OTP verification.
    const second = await start();
    await expect(second.page.locator("#otp")).toBeVisible({ timeout: 20000 });
    expect(callbackCodes).toHaveLength(0);

    // Invalid TOTP: no authorization code and no success.
    const wrong = totp(seed);
    await second.page.locator("#otp").fill(wrong === "000000" ? "111111" : "000000");
    await second.page.locator("#kc-login").click();
    await expect(second.page.locator("#otp")).toBeVisible();
    expect(callbackCodes).toHaveLength(0);

    // Fresh correct factor: actual Keycloak verifier must accept.
    await second.page.locator("#otp").fill(totp(seed));
    await second.page.locator("#kc-login").click();
    await expect.poll(() => callbackCodes.length, { timeout: 20000 }).toBe(1);
    const authorization = callbackCodes.pop()!;
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
    const json = await exchange.json() as { access_token: string; id_token?: string };
    expect(typeof json.access_token).toBe("string");

    // Verify real Keycloak RSA signature using OIDC public JWKS, never payload
    // decode alone. A valid signed ACR remains dependent on reviewed IdP config.
    const metadata = await fetch(issuer + "/.well-known/openid-configuration");
    expect(metadata.ok).toBe(true);
    const jwksUrl = (await metadata.json() as { jwks_uri: string }).jwks_uri;
    const { payload } = await jwtVerify(json.access_token, createRemoteJWKSet(new URL(jwksUrl)), {
      issuer, audience: "temporalmark-approval",
      algorithms: ["RS256", "PS256", "ES256"]
    });
    expect(payload.sub).toBe(expectedSubject);
    expect(payload.acr).toBe(expectedAcr);
    expect(typeof payload.auth_time).toBe("number");
    expect(typeof payload.iat).toBe("number");
    const now = Math.floor(Date.now() / 1000);
    expect(payload.auth_time as number).toBeGreaterThanOrEqual(now - 120);
    expect(payload.auth_time as number).toBeLessThanOrEqual((payload.iat as number) + 30);
    expect(payload.role).toContain("platform_approver");

    // CI-only short-lived ephemeral file for the *actual .NET* JWT verifier
    // and signed-ACR policy. Keep owner-readable 0600; the job trap removes it.
    const file = process.env.TEMPORALMARK_CI_MFA_TOKEN_FILE;
    if (file) writeFileSync(file, json.access_token, { mode: 0o600, flag: "wx" });
    await second.context.close();
  } finally {
    await new Promise<void>(resolve => callbackServer?.close(() => resolve()) ?? resolve());
  }
});
