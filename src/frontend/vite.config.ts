import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "TemporalMark Tenant Console",
        short_name: "TemporalMark",
        description: "Gestione multi-tenant delle evidenze di marca temporale.",
        display: "standalone",
        start_url: "/",
        scope: "/",
        theme_color: "#0f172a",
        background_color: "#f8fafc",
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" }
        ]
      },
      workbox: {
        navigateFallback: "/index.html",
        // API/IdP/health navigations must use the network, NEVER SPA fallback.
        // No protected API response is runtime cached (see ADR 0040 / #71).
        navigateFallbackDenylist: [
          /^\/api(?:\/|$)/,
          /^\/healthz(?:\/|$)/,
          /^\/realms(?:\/|$)/
        ],
        globPatterns: ["**/*.{html,js,css,svg,ico,png}"],
        runtimeCaching: []
      }
    })
  ],
  server: {
    proxy: { "/api": "http://localhost:8080" }
  }
});
