// Script-free enrollment (ADR-0005): both connection types show their ssh
// commands in light and dark, pass axe, and a one-time code never offers a
// script. Screenshots are the THEME-9 evidence.
// @kind:walkthrough
// @feature:enroll
import { test, expect, open, a11y } from '../fixtures.mjs'

async function createCode(page, mode) {
  await open(page, '/enroll')
  await page.getByLabel('Connection type').selectOption(mode)
  await page.getByRole('button', { name: 'Create code' }).click()
  await expect(page.getByRole('heading', { name: /type this on the device/i })).toBeVisible()
}

for (const scheme of ['light', 'dark']) {
  test(`@feature:enroll one-time code shows only ssh commands (${scheme})`, async ({ page }, info) => {
    await page.emulateMedia({ colorScheme: scheme })
    await createCode(page, 'attended')
    await expect(page.getByText('One-time session')).toBeVisible()
    await expect(page.getByRole('tab', { name: /powershell/i })).toHaveCount(0) // no script for a one-time code
    await expect(page.getByText(/StrictHostKeyChecking=yes/).first()).toBeVisible()
    await expect(page.getByText(/Server key fingerprint/)).toContainText('SHA256:')
    await a11y(page)
    await page.screenshot({ path: info.outputPath(`enroll-onetime-unix-${scheme}.png`), fullPage: true })
    await page.getByRole('tab', { name: 'Windows' }).click()
    await expect(page.getByText(/host=%COMPUTERNAME%/).first()).toBeVisible()
    await expect(page.getByText(/Command Prompt/).first()).toBeVisible()
    await a11y(page)
    await page.screenshot({ path: info.outputPath(`enroll-onetime-windows-${scheme}.png`), fullPage: true })
  })

  test(`@feature:enroll install code offers a No script (ssh) tab (${scheme})`, async ({ page }, info) => {
    await page.emulateMedia({ colorScheme: scheme })
    await createCode(page, 'persistent')
    await expect(page.getByRole('tab', { name: /powershell/i })).toHaveCount(1) // the scripts are still there
    await page.getByRole('tab', { name: /no script/i }).click()
    await expect(page.getByText(/ssh-keygen -q -t ed25519/).first()).toBeVisible()
    await expect(page.getByText(/macOS \/ Linux: paste into Terminal/)).toBeVisible()
    await expect(page.getByText(/Windows: paste into Command Prompt/)).toBeVisible()
    await a11y(page)
    await page.screenshot({ path: info.outputPath(`enroll-install-ssh-${scheme}.png`), fullPage: true })
  })
}
