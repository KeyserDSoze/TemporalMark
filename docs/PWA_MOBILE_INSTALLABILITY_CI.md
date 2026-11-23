# Production mobile-emulated PWA manifest/offline regression (#80)

Scope: GitHub CI **disposable Docker/Nginx PWA build**, not a production device-install certification. See [ADR 0048](../adr/0048-stable-pwa-identity-mobile-offline-installability.md), [ADR 0040](../adr/0040-pwa-navigation-fallback-api-denylist.md), parent [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20) and [#80](https://github.com/KeyserDSoze/TemporalMark/issues/80).

## Security / browser contract

The manifest pins `id: "/"`, `start_url: "/"`, `scope: "/"` so a future change of the default landing URL does not inadvertently change the installed application's identity. Its ID is not a tenant/user ID. Chromium's installability metadata includes a name, standalone display, 192×192 and 512×512 PNG icons, and a 512×512 `maskable` purpose. Tests inspect actual linked JSON and the real PNG signatures/width/height over HTTP, not only Vite TypeScript source.

`tests/frontend/pwa-mobile-install.spec.ts` exercises Chromium with the Playwright `Pixel 7` device profile from a **fresh browser context** at the existing loopback Docker/Nginx frontend `http://127.0.0.1:3000`. The test requires a **controlling** production-generated Workbox service worker before going offline. The static application shell must navigate successfully offline, but navigating to an excluded `/api/` route while offline must fail at the network layer or at least never silently return the SPA's cached 200 HTML. Cached keys in all CacheStorage buckets must omit `/api`, `/realms` and `/healthz`. The complementary pre-existing `pwa-navigation-security.spec.ts` tests online backend 404 behavior.

## Reproduce using the disposable Compose stack

Run `docker compose -f docker/compose.yml up -d --build` and ensure the loopback app is available. With the project's pinned Node 22 and `tests/frontend` npm lockfile:

```sh
cd tests/frontend
npm ci --no-audit --no-fund
npx playwright install --with-deps chromium
npx playwright test --config pwa-mobile.config.ts
npx playwright test --config pwa-security.config.ts
```

Both browser tests are excluded from the default Vite-development `playwright.config.ts`: Vite dev does not serve the production generated worker. The GitHub `docker-smoke` CI job runs both against the actual built Compose frontend, and all four jobs must succeed on the **exact final commit SHA** before #80 may close.

## Assumptions / residual threats

- Playwright Android *emulation* does **not** prove a real Android device can present an installation prompt, complete Add to Home Screen, persist an app across OS/browser updates or launch in native standalone mode. It also says nothing about Safari/iOS installation. Physical-device validation and design review of the maskable icon safe area remain #20.
- CacheStorage examination is not an audit of the browser's entire disk/HTTP cache. It does not establish CSP, secure authentication, production HTTPS, server-side `Cache-Control: no-store`, secure WORM custody or cross-tenant data isolation.
- An offline public SPA shell may exist; tenant-specific API responses, OIDC, issuance/evidence and timestamp exports must **never** use a Workbox runtime cache. API authorization remains a *server* boundary, independent of PWA tests.
- No change to V015/V016 registrar issuance suspension, reviewer signed consent, FIDO MDS R46/CRL trusted root, monotonic witness production custody, WORM storage, Azure/on-prem secret management or eIDAS qualified status.

Sources: [MDN Chromium installability requirements](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable), [MDN manifest id](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Manifest/Reference/id).


## HTTP cache response contract independent of offline PWA shell (#186)

The Android-Chromium-emulated installability/offline-shell test observes **CacheStorage only**, not the browser's separate HTTP/disk cache. [ADR 0144](../adr/0144-api-v1-uniform-no-store-http-cache-policy.md) and the [API HTTP cache privacy runbook](API_HTTP_CACHE_PRIVACY.md) now define a **backend** response boundary: every `/api/v1` response should carry `Cache-Control: no-store` (including tenant metadata 200, authentication/validation failures 400/401/403, private 404 and unavailable issuer 503), while public `/healthz` and the installable shell remain functionally unaffected. Test-only genuine signed-Keycloak/real PostgreSQL HTTP [RED 45228057175](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45228057175/attempts/1) identified 18 omissions, preceding one-file app [`17babdb9`](https://github.com/KeyserDSoze/TemporalMark/commit/17babdb9e1c3789ca3215f280a615564d26d5329). A no-store response is **not** proof that a browser destroyed earlier cached data or an OS installation completed; the mobile PWA release gates under #20 remain OPEN.
