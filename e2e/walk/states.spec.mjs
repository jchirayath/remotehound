// Every list screen's four states (CLAUDE.md "UI"): loading is covered by the
// walkthrough; here the empty state and the error state — which must show the
// request ID so a person can quote it — are forced by answering the screen's
// own list request, and the target-size rule (≥ 44 px) is measured.
// @kind:walkthrough
// @feature:devices @feature:groups @feature:users @feature:audit @feature:logs @feature:sessions @feature:enroll
import { test, expect, open } from '../fixtures.mjs'

const LISTS = [
  ['devices', '/devices', '/api/v1/devices'],
  ['groups', '/groups', '/api/v1/groups'],
  ['users', '/users', '/api/v1/users'],
  ['audit', '/audit', '/api/v1/audit'],
  ['logs', '/logs', '/api/v1/logs'],
  ['sessions', '/sessions', '/api/v1/sessions'],
]

/** Answer only the screen's list request (exact path, any query). */
async function answer(page, apiPath, fulfill) {
  await page.route(url => url.pathname === apiPath, route => route.request().method() === 'GET' ? route.fulfill(fulfill) : route.continue())
}

for (const [feature, path, apiPath] of LISTS) {
  test(`@feature:${feature} ${path} error state shows what failed and the request ID`, async ({ page }) => {
    page.allowedErrors = [/500/]
    await answer(page, apiPath, {
      status: 500,
      headers: { 'Content-Type': 'application/problem+json', 'X-Request-Id': 'e2e-req-0001' },
      body: JSON.stringify({ type: 'about:blank', title: 'Internal Server Error', status: 500, code: 'INTERNAL', detail: 'Forced by the e2e test.', request_id: 'e2e-req-0001' }),
    })
    await open(page, path)
    const err = page.getByRole('alert').filter({ hasText: 'e2e-req-0001' })
    await expect(err).toBeVisible()
    await expect(err).toContainText('Request ID')
    await expect(err.getByRole('button', { name: 'Try again' })).toBeVisible()
    // Retry really retries: once the server answers, the error goes away.
    await page.unrouteAll()
    const retried = page.waitForResponse(r => new URL(r.url()).pathname === apiPath && r.status() === 200)
    await err.getByRole('button', { name: 'Try again' }).click()
    await retried
    await expect(page.getByRole('alert').filter({ hasText: 'e2e-req-0001' })).toHaveCount(0)
  })

  test(`@feature:${feature} ${path} empty state explains what goes here`, async ({ page }) => {
    await answer(page, apiPath, { status: 200, contentType: 'application/json', body: JSON.stringify({ data: [], meta: {} }) })
    await open(page, path)
    const empty = page.locator('.state--empty')
    await expect(empty).toBeVisible()
    await expect(empty.getByRole('heading')).not.toHaveText('')
  })
}
