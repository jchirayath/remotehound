// Target size on every screen (CLAUDE.md "UI": ≥ 44 px targets; WCAG 2.5.5): every visible
// control a person can click or tap is at least --touch (44 px) in both directions, on the
// desktop and the phone layout. A radio or checkbox counts through its label, which is the target.
// @kind:walkthrough
// @feature:overview @feature:devices @feature:enroll @feature:sessions @feature:groups @feature:users
// @feature:integration @feature:logs @feature:debug @feature:settings @feature:audit @feature:help @feature:services
import { test, expect, open } from '../fixtures.mjs'

const SCREENS = ['/', '/devices', '/enroll', '/sessions', '/groups', '/users', '/integration', '/logs',
  '/debug', '/settings', '/audit', '/profile', '/services']
const MIN = 44

/** Visible interactive elements smaller than MIN px, described for the failure message. */
async function smallTargets(page) {
  // Dialogs open with a short scale-in animation: measure the settled size, not a frame of it.
  // (Endless decorative animations, like the Overview's glow, never settle and change no sizes.)
  await page.waitForFunction(() => document.getAnimations()
    .filter(a => a.effect?.getComputedTiming().iterations !== Infinity)
    .every(a => a.playState !== 'running'))
  return page.evaluate((min) => {
    const sel = 'a[href], button, input:not([type=hidden]), select, textarea, [role=button], [role=tab], [role=switch], summary'
    const out = []
    for (const el of document.querySelectorAll(sel)) {
      let target = el
      // Visually hidden native inputs (radios, checkboxes, switches) are operated through their label.
      if (el.matches('input[type=radio], input[type=checkbox]') && el.labels?.length) target = el.labels[0]
      const r = target.getBoundingClientRect()
      const st = getComputedStyle(target)
      if (r.width === 0 || r.height === 0 || st.visibility === 'hidden' || st.display === 'none') continue
      if (target.closest('[hidden], [aria-hidden="true"]')) continue
      // A skip link is only on screen while focused.
      if (target.matches('.skip-link') && document.activeElement !== target) continue
      if (r.width + 0.5 < min || r.height + 0.5 < min) {
        const name = (target.getAttribute('aria-label') || target.textContent || target.getAttribute('placeholder') || '').trim().replace(/\s+/g, ' ').slice(0, 40)
        out.push(`${target.tagName.toLowerCase()}.${String(target.className || '').split(' ')[0]} "${name}" ${Math.round(r.width)}×${Math.round(r.height)}`)
      }
    }
    return out
  }, MIN)
}

for (const path of SCREENS) {
  test(`@feature:help every target on ${path} is at least ${MIN} px`, async ({ page }) => {
    await open(page, path)
    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0) // loading states finished
    expect(await smallTargets(page)).toEqual([])
  })
}

test('@feature:help @feature:groups drawers, confirm dialogs and the help panel keep full-size targets', async ({ page }) => {
  await open(page, '/groups')
  await page.getByRole('button', { name: 'New group' }).click() // a drawer with a form
  await expect(page.getByRole('dialog', { name: 'New group' })).toBeVisible()
  expect(await smallTargets(page)).toEqual([])
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: /^Delete / }).first().click() // a confirm dialog
  await expect(page.getByRole('alertdialog')).toBeVisible()
  expect(await smallTargets(page)).toEqual([])
  await page.getByRole('alertdialog').getByRole('button', { name: 'Cancel' }).click()
  await page.getByRole('button', { name: /help/i }).first().click() // the help panel
  await expect(page.getByRole('dialog')).toBeVisible()
  expect(await smallTargets(page)).toEqual([])
})

test('@feature:help a wide system font shortens names, never buttons', async ({ page }) => {
  // CI's Linux fonts are wider than macOS's: the brand squeezed "Collapse sidebar" to 23 px there.
  await open(page, '/')
  await page.evaluate(() => { document.body.style.letterSpacing = '0.12em' }) // CSSOM: allowed by the page's CSP
  expect(await smallTargets(page)).toEqual([])
})

test('@feature:help the skip link is a full-size target when focused', async ({ page }) => {
  await open(page, '/')
  const skip = page.locator('.skip-link')
  await skip.focus() // the app moves focus to the page heading after load, so focus the link directly
  await expect(skip).toBeFocused()
  const box = await skip.boundingBox()
  expect(box.height).toBeGreaterThanOrEqual(MIN)
})
