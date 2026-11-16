# ADR 0048 — Stable PWA app identity and mobile-emulated production offline installability regression

Status: **accepted for limited PWA delivery verification, not native OS installation**, 2026-11-16. Child [#80](https://github.com/KeyserDSoze/TemporalMark/issues/80) of open [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20).

Reviewed ADR 0001/0003/0040/0043–0047, `docs/PWA_SERVICE_WORKER_SECURITY.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`, Vite's current manifest and Workbox settings, `tests/frontend/pwa-navigation-security.spec.ts`, the Chromium Playwright setup, all four CI jobs and on-prem/Azure deployment constraints.

## Problem

The PWA specifies `start_url: "/"` but **no explicit manifest `id`**. Browsers can derive app identity from `start_url`, making future start-route changes potentially alter installed-app identity. Existing desktop service-worker integration guards /api navigation but does not test the delivered manifest or PNG pixel dimensions on a mobile-emulated browser, nor whether offline navigation still uses the static shell without leaking sensitive routes to CacheStorage. An icon manifest declaration alone does not prove the PNG is served with those actual dimensions.

## Decision

1. Explicitly pin **`manifest.id: "/"`**, retaining `start_url: "/"` and `scope: "/"` for the same origin. Keep app name, standalone display, 192/512 PNG icons, 512 maskable declaration, and existing `runtimeCaching: []` + `navigateFallbackDenylist` for API/OIDC/health. This is a stable app ID, **not** a user/tenant-specific tracking ID.
2. Use a separate Playwright `pwa-mobile.config.ts` with **Chromium emulating an Android mobile viewport** against the *actual Docker/Nginx production build* at `http://127.0.0.1:3000` (loopback secure context). This is NOT Vite dev mode, an Android system install test or an iOS Add to Home Screen test. Check actual linked manifest as served by Nginx, explicit stable `id` and scope, required installability fields, 192 and 512 PNG HTTP bytes, signatures/dimensions and maskable purpose. Reject same-origin violations when fetching icon declarations.
3. Require an active **controlling Workbox worker**, then offline navigation to `/` must use cached static SPA shell; an offline API navigation may throw an offline network error but must **not** return 200 + cached SPA shell. Across CacheStorage buckets, exclude `/api`, `/realms` and `/healthz`. Existing online production API navigation denylist test remains unchanged.
4. TDD: record ADR then add RED browser regression and CI invocation while manifest has no `id`; capture CI failure specifically on missing `manifest.id`. GREEN adds the one-line `id`, documents test caveats, then requires exact-final-main-SHA backend/frontend/docker-smoke/terraform GREEN before closing only #80. Keep #20 open for **true device install/UX, release attestation, SAST/secret scanning and cross-tenant API**.
5. Do not change any SQL migrations or reviewer/registrar issuance. Keep V015/V016 fail-closed, #38/#44/#46/#50, #57/#61/#64, WORM #17, QTSP #13 open. On-prem and Azure keep the same PWA manifest contract; production HTTPS and CSP/headers require their own review.

## Limitations and sources

A mobile Chromium device profile does not install an application on Android/iOS or prove browser-specific native prompts, OS lifecycle, user approval, push, service worker integrity at every client, PWA distribution, evidentiary WORM or qualification. CacheStorage is not the browser's entire HTTP/disk cache. Maskable purpose metadata does **not** independently prove safe artwork composition; a separate design review is still required. Offline API fallback guards are **not server-side authorization**; tenant isolation/RLS is independent.

References: [MDN installability requirements](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable), [MDN manifest id](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Manifest/Reference/id), [W3C Web Application Manifest 2026 draft](https://www.w3.org/TR/2026/WD-appmanifest-20261111/), [existing ADR 0040](0040-pwa-navigation-fallback-api-denylist.md).
