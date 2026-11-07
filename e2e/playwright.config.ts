import { defineConfig, devices } from "@playwright/test";

// Run through scripts/e2e.sh, which starts the compose stack and sets E2E_* variables.
export default defineConfig({
  testDir: "tests",
  globalSetup: "./global-setup.ts",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  retries: 0, // a flaky test is a failed test
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost:59443",
    ignoreHTTPSErrors: true, // Caddy's internal CA for localhost
    locale: "en-US",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", testIgnore: /admin\.spec/, use: { ...devices["Desktop Chrome"] } },
    // admin.spec changes site-wide rules (forbid download): it runs alone, after all other specs
    { name: "admin", testMatch: /admin\.spec/, dependencies: ["chromium"], use: { ...devices["Desktop Chrome"] } },
  ],
});
