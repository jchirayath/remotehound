// Device setup guide: Enroll > "Setup guide" opens the printable guide filled in with the new
// code, for that machine type only, and the code never appears in the guide's URL.
// Screenshots are the walkthrough evidence; the guide is a light-only print document.
// @kind:walkthrough
// @feature:enroll
import { test, expect, open, a11y } from '../fixtures.mjs'

async function createCode(page, os) {
  await open(page, '/enroll')
  await page.getByLabel('Machine type').selectOption(os)
  await page.getByRole('button', { name: 'Create code' }).click()
  await expect(page.getByRole('heading', { name: /type this on the device/i })).toBeVisible()
  return (await page.getByRole('img', { name: /Enrollment code/ }).getAttribute('aria-label')).replace(/^Enrollment code /, '').replace(/ /g, '')
}

for (const [os, shown, hidden] of [['macos', 'On a Mac', 'On a Windows PC'], ['windows', 'On a Windows PC', 'On a Mac']]) {
  test(`@feature:enroll setup guide is filled in for a ${os} code`, async ({ page }, info) => {
    const code = await createCode(page, os)
    const [guide] = await Promise.all([page.waitForEvent('popup'), page.getByRole('button', { name: 'Setup guide' }).click()])
    await expect(guide.locator('html')).toHaveAttribute('data-state', 'filled')
    expect(guide.url()).not.toContain(code) // handed over by postMessage, never in the URL
    await expect(guide.locator('[data-fill="slots"]')).toHaveText(code)
    await expect(guide.locator('.cmd [data-fill="code"]').first()).toHaveText(code)
    await expect(guide.getByRole('heading', { name: shown })).toBeVisible()
    await expect(guide.getByRole('heading', { name: hidden })).toBeHidden()
    await expect(guide.locator('[data-fill="base"]').first()).toHaveText(/^https?:\/\//)
    expect(new URL(await guide.locator('[data-fill="base"]').first().textContent()).host).toBeTruthy()
    await expect(guide.getByRole('button', { name: /print or save as pdf/i })).toBeVisible()
    await a11y(guide)
    await guide.screenshot({ path: info.outputPath(`enroll-guide-${os}.png`), fullPage: true })
  })
}

test('@feature:enroll setup guide opened directly stays blank, with this server\'s address', async ({ page }) => {
  await open(page, '/enroll')
  await page.goto('/ui/guide/device-setup.html?base=https://evil.example.com')
  await expect(page.locator('html')).toHaveAttribute('data-state', 'blank')
  await expect(page.locator('[data-fill="base"]').first()).toHaveText(new URL(page.url()).origin)
  await expect(page.locator('.cmd [data-fill="code"]').first()).toHaveText('CODE')
})
