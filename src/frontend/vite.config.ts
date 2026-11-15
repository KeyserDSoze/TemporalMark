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
          { src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any maskable" }
        ]
      },
      workbox: {
        navigateFallback: "/index.html",
        globPatterns: ["**/*.{html,js,css,svg,ico,png}"],
        runtimeCaching: []
      }
    })
  ],
  server: {
    proxy: { "/api": "http://localhost:8080" }
  }
});
