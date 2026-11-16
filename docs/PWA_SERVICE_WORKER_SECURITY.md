# Production PWA: fail-closed API navigation fallback (#71)

**Scope:** React/Vite PWA and disposable production-build Playwright test only. [ADR 0040](../adr/0040-pwa-navigation-fallback-api-denylist.md) and [issue #71](https://github.com/KeyserDSoze/TemporalMark/issues/71) (child of ongoing [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20)).

## Risk and fixed behavior

The existing `vite-plugin-pwa` Workbox `navigateFallback: "/index.html"` caches the public SPA shell for navigation requests. In a real Chromium browser with an ACTIVE, CONTROLLING worker, a navigation to `/api/__pwa_navigation_denylist_probe__` incorrectly returned **200** instead of the backend's **404**: [RED CI on `fd501c9`](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43842598997). The backend was not returning that success response, so this is a service-worker route collision, **not evidence that sensitive API bodies were cached**.

The worker now uses Workbox `navigateFallbackDenylist` with anchored paths `/api`, `/healthz` and `/realms` (including their child paths). These URLs **must use network routing** or fail offline; they may never be silently substituted with the precached SPA HTML. The original `runtimeCaching: []` stays empty: no new runtime caches or background-sync queues for API, exports, OIDC or timestamp tokens. Only the static SPA assets remain precached. The Nginx upstream mapping and API authorization remain unchanged.

## Real regression and reproduction

The dedicated test is `tests/frontend/pwa-navigation-security.spec.ts` configured by `pwa-security.config.ts`. It is intentionally excluded from the default Vite-development Playwright suite because dev mode is not a substitute for the GENERATED Workbox service worker. In the `docker-smoke` GitHub Actions job, after Docker app/frontend health and installing Chromium, run:

```sh
cd tests/frontend
npx playwright test --config pwa-security.config.ts
```

The test loads the Nginx-built app, awaits `navigator.serviceWorker.ready`, reloads and **requires an active controlling worker**, then navigates to an unimplemented same-origin `/api/` URL with the browser's natural navigation headers. The actual backend response must be **404**, never `200 index.html`. The test returns to the SPA and inspects all CacheStorage buckets, denying any cached `/api` URLs. No test tokens or private customer evidence are used. Run the COMPLETE four-job CI on the exact final `main` SHA; track results and close only #71 when all are GREEN.

## Limits

Service workers are origin-scoped client code; this denylist is a defense against navigation fallback confusion, **not server-side authorization, tenant RLS, secure caching headers, CSP or a substitute for evidence secrecy**. Existing browser disk/HTTP caches, stale workers, malicious extensions, cross-origin Keycloak and offline update recovery require separate risk assessment. Child #74 pins GitHub Action SHAs; child #75 adds npm lockfileVersion 3 and npm ci. Remaining #20 work includes container digests, mobile PWA installation, SAST/SBOM, release attestations and authenticated cross-tenant coverage. FIDO/witness release blockers #64/#61/#57 and V015/V016 registrar freeze remain untouched. This does not deliver WORM, eIDAS, QTSP qualification or approved FIDO metadata trust.

References: [vite-plugin-pwa navigation denylist](https://vite-pwa-org.netlify.app/workbox/generate-sw), [Chrome Workbox GenerateSW](https://developer.chrome.com/docs/workbox/modules/workbox-build).
