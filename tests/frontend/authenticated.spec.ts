import { test, expect } from "@playwright/test";

test("development tenant administrator authenticates and sees own registry", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Accedi con la tua organizzazione" }).click();
  await expect(page).toHaveURL(/localhost:8081/);

  await page.locator("#username").fill("demo-admin");
  await page.locator("#password").fill("local-dev-only");
  await page.locator("#kc-login").click();

  // This tests full OIDC + real database membership, not just a mocked API.
  try {
    await expect(page.getByText("11111111-1111-1111-1111-111111111111")).toBeVisible({ timeout: 30000 });
  } catch (failure) {
    // Never log query strings (OIDC authorization codes), tokens or credentials.
    const route = new URL(page.url());
    console.log("Auth diagnostic path:", route.origin + route.pathname);
    console.log("Auth diagnostic visible page:", (await page.locator("body").innerText()).slice(0, 1600));
    throw failure;
  }
  await expect(page.getByText("Nessuna marca registrata nel periodo selezionato.")).toBeVisible();
  await expect(page.getByText("Servizio NON qualificato")).toBeVisible();
  await expect(page.getByText("Cronologia accessi alle evidenze")).toBeVisible();
  // Real signed-Keycloak session, empty tenant registry: one accessible
  // zero-valued bar for every day in the default 30-day UTC window.
  const chart = page.getByRole("group", { name: "Marche registrate per giorno (UTC)" });
  await expect(chart).toBeVisible();
  await expect(chart.getByRole("img")).toHaveCount(30);

  // A longer period must not fail summary/registry/audit/export merely
  // because the daily aggregate is deliberately capped at 31 days.
  await page.locator('input[type="date"]').nth(0).fill("2026-01-01");
  await page.locator('input[type="date"]').nth(1).fill("2026-03-01");
  await page.getByRole("button", { name: "Applica filtri" }).click();
  await expect(page.getByText(/Il grafico giornaliero mostra fino a 31 giorni UTC/)).toBeVisible();
  await expect(page.getByText("Nessuna marca registrata nel periodo selezionato.")).toBeVisible();

  // Restore a UTC window containing *now* before asserting the audit event
  // produced by the next ZIP export. The long-range January/March filter
  // deliberately excludes that event in a November runner; that is correct
  // audit filtering, not a product bug. Do not weaken the audit predicate.
  const utcToday = new Date();
  const utcFrom = new Date(utcToday);
  utcFrom.setUTCDate(utcFrom.getUTCDate() - 29);
  await page.locator('input[type="date"]').nth(0).fill(utcFrom.toISOString().slice(0, 10));
  await page.locator('input[type="date"]').nth(1).fill(utcToday.toISOString().slice(0, 10));
  await page.getByRole("button", { name: "Applica filtri" }).click();
  await expect(chart).toBeVisible();
  await expect(chart.getByRole("img")).toHaveCount(30);

  // Exporting an empty registry is still a tenant-sensitive operation.
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Esporta ZIP del periodo" }).click();
  const receipt = await download;
  expect(receipt.suggestedFilename()).toMatch(/^temporalmark-.*\.zip$/);
  await expect(page.getByText("Esportazione predisposta")).toBeVisible({ timeout: 15000 });

  await page.locator('input[type="file"]').setInputFiles({
    name: "example.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("private local test document")
  });
  await page.getByRole("button", { name: "Richiedi marca esterna" }).click();
  await expect(page.getByText(/Nessuna TSA esterna configurata/)).toBeVisible();

  // RED-first #111, UI-only pagination fixture AFTER real OIDC, database
  // authorization, receipt/export and disabled-TSA checks above. These
  // test-only route mocks do NOT count as evidence of server tenant isolation.
  const registered = Array.from({ length: 51 }, (_, i) => ({
    id: `00000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}`,
    issuedUtc: new Date().toISOString(),
    digestBase64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    providerId: `CI_PAGE_${String(i + 1).padStart(2, "0")}`,
    validationState: "Unverified"
  }));
  const offsets: number[] = [];
  let holdAnOldSecondPage = false;
  let notifyOldPageRequested: () => void = () => {};
  let releaseOldPage: () => void = () => {};
  let notifyOldPageServed: () => void = () => {};
  const oldPageRequested = new Promise<void>(resolve => { notifyOldPageRequested = resolve; });
  const oldPageRelease = new Promise<void>(resolve => { releaseOldPage = resolve; });
  const oldPageServed = new Promise<void>(resolve => { notifyOldPageServed = resolve; });
  await page.route("**/api/v1/stamps/summary?*", async route => {
    await route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ organizationId: "11111111-1111-1111-1111-111111111111", count: 51 })
    });
  });
  await page.route("**/api/v1/stamps?*", async route => {
    const offset = Number(new URL(route.request().url()).searchParams.get("offset") ?? "0");
    offsets.push(offset);
    const isDelayed = offset === 50 && holdAnOldSecondPage;
    if (isDelayed) {
      holdAnOldSecondPage = false;
      notifyOldPageRequested();
      await oldPageRelease;
    }
    await route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify(registered.slice(offset, offset + 50))
    });
    if (isDelayed) notifyOldPageServed();
  });
  await page.getByRole("button", { name: "Applica filtri" }).click();
  await expect(page.getByText("CI_PAGE_01")).toBeVisible();
  await expect(page.getByText("CI_PAGE_51")).toHaveCount(0);
  await expect(page.getByText("1–50 di 51")).toBeVisible();
  await page.getByRole("button", { name: "Pagina successiva" }).click();
  await expect(page.getByText("CI_PAGE_51")).toBeVisible();
  await expect(page.getByText("CI_PAGE_01")).toHaveCount(0);
  await expect(page.getByText("51–51 di 51")).toBeVisible();
  await expect(page.getByRole("button", { name: "Pagina successiva" })).toBeDisabled();
  await page.getByRole("button", { name: "Pagina precedente" }).click();
  await expect(page.getByText("CI_PAGE_01")).toBeVisible();
  await expect(page.getByText("CI_PAGE_51")).toHaveCount(0);
  expect(offsets).toContain(0);
  expect(offsets).toContain(50);
  expect(offsets.at(-1)).toBe(0);

  // Changing a period resets navigation to the first authorized page.
  await page.getByRole("button", { name: "Pagina successiva" }).click();
  await expect(page.getByText("CI_PAGE_51")).toBeVisible();
  const shiftedFrom = new Date();
  shiftedFrom.setUTCDate(shiftedFrom.getUTCDate() - 28);
  await page.locator('input[type="date"]').nth(0).fill(shiftedFrom.toISOString().slice(0, 10));
  await expect(page.getByText("CI_PAGE_01")).toBeVisible();
  await expect(page.getByText("1–50 di 51")).toBeVisible();
  expect(offsets.at(-1)).toBe(0);

  // An old, slow second-page response must never replace the latest
  // authorized filter's first page. Hold just one test-only response.
  holdAnOldSecondPage = true;
  await page.getByRole("button", { name: "Pagina successiva" }).click();
  await oldPageRequested;
  const newerFrom = new Date();
  newerFrom.setUTCDate(newerFrom.getUTCDate() - 27);
  await page.locator('input[type="date"]').nth(0).fill(newerFrom.toISOString().slice(0, 10));
  await expect(page.getByText("CI_PAGE_01")).toBeVisible();
  releaseOldPage();
  await oldPageServed;
  await page.waitForTimeout(150); // allow the deliberately stale response to settle
  await expect(page.getByText("CI_PAGE_51")).toHaveCount(0);
  await expect(page.getByText("1–50 di 51")).toBeVisible();
  expect(offsets.at(-1)).toBe(0);
});
