// Walkthrough per screen (TEST-6 / TEST-13 / THEME-9): open as admin, assert
// it renders authenticated with no console errors, open its help, run axe
// (zero serious), screenshot light + dark; then the denied path as an operator.
// @kind:walkthrough
// @feature:overview @feature:devices @feature:enroll @feature:sessions @feature:groups @feature:users
// @feature:integration @feature:logs @feature:debug @feature:settings @feature:audit @feature:help @feature:services
import { test, expect, open, a11y, OPERATOR } from '../fixtures.mjs'

const SCREENS = [
  ['overview', '/'], ['devices', '/devices'], ['enroll', '/enroll'], ['sessions', '/sessions'],
  ['groups', '/groups'], ['users', '/users'], ['integration', '/integration'], ['logs', '/logs'],
  ['debug', '/debug'], ['settings', '/settings'], ['audit', '/audit'], ['help', '/profile'], ['services', '/services'],
]

for (const [feature, path] of SCREENS) {
  test(`@feature:${feature} walkthrough ${path}`, async ({ page }, info) => {
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: scheme })
      await open(page, path)
      await expect(page.locator('[aria-busy="true"]')).toHaveCount(0) // loading states finished
      await a11y(page)
      await page.screenshot({ path: info.outputPath(`${feature}-${scheme}.png`), fullPage: true })
    }
    await page.getByRole('button', { name: /help/i }).first().click()
    await expect(page.getByRole('dialog')).toBeVisible()
  })
}

// Denied paths: an operator cannot reach admin screens or admin data.
for (const [feature, path] of [['settings', '/settings'], ['users', '/users'], ['audit', '/audit'], ['debug', '/debug'], ['services', '/services']]) {
  test(`@feature:${feature} operator is denied ${path}`, async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: OPERATOR })
    const page = await ctx.newPage()
    page.allowedErrors = [/403|Forbidden/]
    await page.goto(path)
    await expect(page.getByText(/no access|not allowed|cannot|permission|don.t have/i).first()).toBeVisible()
    await ctx.close()
  })
}

test('@feature:sessions operator sees only their own and shared sessions', async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: OPERATOR })
  const page = await ctx.newPage()
  await page.goto('/sessions')
  await expect(page.getByRole('tab', { name: /mine/i })).toBeVisible()
  await expect(page.getByRole('tab', { name: /all sessions/i })).toHaveCount(0)
  await ctx.close()
})

test('@feature:services the signed-out page renders with no session and offers sign-in', async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
  const page = await ctx.newPage()
  await page.goto('/signed-out')
  await expect(page.getByRole('heading', { name: /signed out/i })).toBeVisible()
  await expect(page.getByRole('link', { name: /sign in again/i })).toBeVisible()
  await page.goto('/signed-out?reason=proxy')
  await expect(page.getByRole('heading', { name: /did not reach remotehound/i })).toBeVisible()
  await ctx.close()
})
