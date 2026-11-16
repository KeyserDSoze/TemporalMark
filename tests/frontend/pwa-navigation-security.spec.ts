import { test, expect } from "@playwright/test";

/**
 * Production PWA regression: navigational requests for /api/ must reach the
 * backend, not Workbox's offline SPA index.html fallback. A fresh browser
 * context is used; no real customer evidence or bearer tokens are needed.
 */
test("controlling service worker must not serve cached SPA for API navigation", async ({ page }) => {
  const initial = await page.goto("/");
  expect(initial?.status()).toBe(200);
  await expect(page.getByText("Servizio NON qualificato")).toBeVisible();

  // The dev server does not install the production Workbox worker. This
  // test intentionally targets Docker/Nginx's built frontend instead.
  await page.evaluate(async () => {
    if (!("serviceWorker" in navigator)) {
      throw new Error("No ServiceWorker support in production PWA browser");
    }
    await navigator.serviceWorker.ready;
  });
  await page.reload();
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);

  // A browser navigation sends an HTML-oriented Accept header; without a
  // denylist Workbox may answer this API request with precached index.html.
  const networkOnly = await page.goto("/api/__pwa_navigation_denylist_probe__");
  expect(networkOnly).not.toBeNull();
  expect(networkOnly!.status()).toBe(404);
  const responseBody = await networkOnly!.text();
  expect(responseBody).not.toContain('<div id="root">');

  // Static shell navigation still works; no API URL enters CacheStorage.
  const backToApp = await page.goto("/");
  expect(backToApp?.status()).toBe(200);
  const apiCachedUrls = await page.evaluate(async () => {
    const found: string[] = [];
    for (const name of await caches.keys()) {
      const bucket = await caches.open(name);
      for (const entry of await bucket.keys()) {
        const url = new URL(entry.url);
        if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
          found.push(entry.url);
        }
      }
    }
    return found;
  });
  expect(apiCachedUrls).toEqual([]);
});
