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
    // ERR_ABORTED is the browser cancelling an in-flight request because the test moved on (navigated,
    // switched color scheme). Over a real network (e2e/azure) that is routine; a server failure shows
    // up as an HTTP error status or a connection error instead, which still fails the test.
    page.on('requestfailed', r => {
      const why = r.failure()?.errorText || ''
      // A test may also name errors it expects (page.allowedErrors), for failed requests as for console lines.
      if (!/\/api\/v1\/logs\/stream/.test(r.url()) && !/ERR_ABORTED/.test(why) && !page.allowedErrors?.some(x => x.test(why))) problems.push('requestfailed: ' + r.url() + ' ' + why)
    })
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

/** A fresh ed25519 public key in OpenSSH authorized_keys form. */
export async function sshPublicKey() {
  const { publicKey } = (await import('node:crypto')).generateKeyPairSync('ed25519')
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12)
  const blob = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), raw])
  return 'ssh-ed25519 ' + blob.toString('base64')
}

/**
 * Enroll a device through the real API (it never connects, so it stays offline).
 * Returns the device ID.
 */
export async function enrolDevice(request, { name, os = 'linux', groupId, services = [{ kind: 'ssh', remote_port: 22 }] }) {
  const enr = (await api(request, ADMIN, 'POST', '/api/v1/enrollments', { name, ...(groupId ? { group_id: groupId } : {}) })).body.data
  const res = await request.post(ADMIN + '/api/v1/enroll', { ignoreHTTPSErrors: true, data: { code: enr.code, public_key: await sshPublicKey(), hostname: name, os, services } })
  expect(res.status()).toBe(201)
  return (await res.json()).data.device_id
}

/** Audit events named `event` for `resource` (e.g. "group:grp_…"). */
export async function auditFor(request, event, resource) {
  const r = await api(request, ADMIN, 'GET', `/api/v1/audit?page_size=500&event=${encodeURIComponent(event)}`)
  return r.body.data.filter(e => e.event === event && e.resource === resource)
}
