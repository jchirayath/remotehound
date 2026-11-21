// Browser tests run against the live bundle started with the TEST-ONLY overlay:
//   cd deploy && docker compose -f compose.yml -f test/compose.e2e.yml --env-file test/e2e.env up -d --build
// :8443 is signed in as admin@example.com, :8444 as op@example.com (operator) — see deploy/test/Caddyfile.e2e.
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: ['journeys/**/*.spec.mjs', 'walk/**/*.spec.mjs'],
  globalSetup: './global-setup.mjs',
  timeout: 45_000,
  retries: 0, // flaky tests are quarantined, never retried (TEST-5)
  workers: 1, // tests share one live bundle and its state
  reporter: [['list']],
  use: {
    baseURL: process.env.RH_E2E_URL || 'https://localhost:8443',
    ignoreHTTPSErrors: true, // Caddy's local CA
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], channel: 'chrome' } },
    { name: 'phone', use: { ...devices['Pixel 7'], channel: 'chrome' }, testMatch: ['walk/**/*.spec.mjs'] },
  ],
})
