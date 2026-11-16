import { test, expect } from "@playwright/test";

/**
 * Production-build Android-Chromium emulation, not native Android/iOS installation.
 * Uses the actual linked manifest, HTTP PNG bytes and controlling Workbox worker.
 * Do not run against Vite dev, which does not serve the generated worker.
 */
test("mobile PWA has stable identity, real install icons and offline-safe shell", async ({ page, context }) => {
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  expect(await page.evaluate(() => window.isSecureContext)).toBe(true);

  const manifestLink = page.locator('link[rel="manifest"]');
  await expect(manifestLink).toHaveCount(1);
  const href = await manifestLink.getAttribute("href");
  expect(href).toBeTruthy();
  const manifestUrl = new URL(href!, page.url());
  expect(manifestUrl.origin).toBe(new URL(page.url()).origin);

  const manifestResponse = await page.request.get(manifestUrl.href);
  expect(manifestResponse.status()).toBe(200);
  const manifest: {
    id?: string; name?: string; short_name?: string; start_url?: string;
    scope?: string; display?: string; prefer_related_applications?: boolean;
    icons?: { src: string; sizes: string; type: string; purpose?: string }[];
  } = await manifestResponse.json();

  // RED on the original manifest: implicit start_url-derived identity is
  // not an explicit stable app ID (ADR 0048 / #80).
  expect(manifest.id).toBe("/");
  expect(manifest.start_url).toBe("/");
  expect(manifest.scope).toBe("/");
  expect(manifest.display).toBe("standalone");
  expect(manifest.name || manifest.short_name).toBeTruthy();
  expect(manifest.prefer_related_applications).not.toBe(true);

  const icons = manifest.icons ?? [];
  for (const pixels of [192, 512]) {
    const icon = icons.find(item =>
      item.type === "image/png" &&
      item.sizes.split(/\s+/).includes(`${pixels}x${pixels}`) &&
      (item.purpose ?? "any").split(/\s+/).includes("any"));
    expect(icon, `missing ${pixels}x${pixels} PNG any icon`).toBeDefined();
    const iconUrl = new URL(icon!.src, manifestUrl);
    expect(iconUrl.origin).toBe(manifestUrl.origin);
    const imageResponse = await page.request.get(iconUrl.href);
    expect(imageResponse.status()).toBe(200);
    const bytes = await imageResponse.body();
    expect(bytes.length).toBeGreaterThan(24);
    expect(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))).toBe(true);
    expect(bytes.readUInt32BE(16)).toBe(pixels);
    expect(bytes.readUInt32BE(20)).toBe(pixels);
  }
  expect(icons.some(icon =>
    icon.type === "image/png" &&
    icon.sizes.split(/\s+/).includes("512x512") &&
    (icon.purpose ?? "").split(/\s+/).includes("maskable"))).toBe(true);

  await page.evaluate(async () => {
    if (!("serviceWorker" in navigator)) throw new Error("ServiceWorker unsupported");
    await navigator.serviceWorker.ready;
  });
  await page.reload();
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);

  const protectedPaths = ["/api", "/realms", "/healthz"];
  const cachedProtected = await page.evaluate(async prefixes => {
    const found: string[] = [];
    for (const cacheName of await caches.keys()) {
      const cache = await caches.open(cacheName);
      for (const request of await cache.keys()) {
        const path = new URL(request.url).pathname;
        if (prefixes.some(prefix => path === prefix || path.startsWith(prefix + "/"))) found.push(request.url);
      }
    }
    return found;
  }, protectedPaths);
  expect(cachedProtected).toEqual([]);

  await context.setOffline(true);
  try {
    const offline = await page.goto("/");
    expect(offline?.status()).toBe(200);
    expect(await offline!.text()).toContain('<div id="root"></div>');

    // Excluded API navigation must fail at the network layer offline, or
    // at least never return a successful cached SPA HTML document.
    let apiResult: Awaited<ReturnType<typeof page.goto>> = null;
    let networkError = "";
    try {
      apiResult = await page.goto("/api/__pwa_mobile_offline_probe__");
    } catch (error) {
      networkError = String(error);
    }
    if (networkError) {
      expect(networkError).toMatch(/net::ERR_(?:INTERNET_DISCONNECTED|FAILED|ABORTED)/);
    } else {
      expect(apiResult).not.toBeNull();
      expect(apiResult!.status()).not.toBe(200);
      expect(await apiResult!.text()).not.toContain('<div id="root"></div>');
    }
  } finally {
    await context.setOffline(false);
  }
});
