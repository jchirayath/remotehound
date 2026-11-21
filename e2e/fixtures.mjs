// Shared e2e helpers. Every test asserts the page is authenticated (not /login),
// and fails on console errors, uncaught exceptions and failed requests (TEST-4).
import { test as base, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

export const ADMIN = process.env.RH_E2E_URL || 'https://localhost:8443'
export const OPERATOR = process.env.RH_E2E_OPERATOR_URL || 'https://localhost:8444'

export const test = base.extend({
  page: async ({ page }, use) => {
    const problems = []
    page.on('console', m => { if (m.type() === 'error' && !page.allowedErrors?.some(r => r.test(m.text()))) problems.push('console: ' + m.text()) })
    page.on('pageerror', e => problems.push('pageerror: ' + e.message))
    page.on('requestfailed', r => { if (!/\/api\/v1\/logs\/stream/.test(r.url())) problems.push('requestfailed: ' + r.url() + ' ' + r.failure()?.errorText) })
    await use(page)
    expect(problems, problems.join('\n')).toEqual([])
  },
})
export { expect }

/** API helper using the stamped identity behind origin; returns parsed data. */
export async function api(request, origin, method, path, body) {
  const me = await request.get(origin + '/api/v1/me', { ignoreHTTPSErrors: true })
  const csrf = (await me.json()).data?.csrf_token
  const res = await request.fetch(origin + path, { method, data: body, ignoreHTTPSErrors: true, headers: { 'X-CSRF-Token': csrf || '', 'Content-Type': 'application/json' } })
  const text = await res.text()
  return { status: res.status(), body: text ? JSON.parse(text) : null }
}

/** Open a screen and assert it rendered for a signed-in user. */
export async function open(page, path) {
  await page.goto(path)
  await expect(page).not.toHaveURL(/\/login/)
  await expect(page.locator('h1').first()).toBeVisible()
}

/** WCAG 2.2 AA scan: no serious or critical violations (TEST-13). */
export async function a11y(page) {
  const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
  const bad = r.violations.filter(v => ['serious', 'critical'].includes(v.impact))
  expect(bad.map(v => `${v.id}: ${v.nodes.length} × ${v.help}`)).toEqual([])
}
