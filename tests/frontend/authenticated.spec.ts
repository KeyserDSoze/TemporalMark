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
});
