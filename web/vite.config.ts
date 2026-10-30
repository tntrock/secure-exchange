/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "../internal/webui/dist", emptyOutDir: true },
  server: { proxy: { "/api": "http://localhost:8080" } },
  test: {
    environment: "jsdom",
    coverage: { provider: "v8", reporter: ["text-summary", "lcov"], include: ["src/**"], exclude: ["src/main.tsx", "src/**/*.test.*"], thresholds: { statements: 90, lines: 90 } },
  },
});
