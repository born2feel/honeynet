/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev the dashboard runs on :5173 and proxies the API to a local honeynet
// started with `-origins localhost:5173` (needed for the WebSocket origin check).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:9000", ws: true },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 800,
  },
  test: {
    environment: "node",
  },
});
