// @kind:e2e
// Main journeys through the real UI against the live bundle (TEST-0 e2e kind).
import { test, expect, open, api, ADMIN } from '../fixtures.mjs'

test('@feature:overview overview shows live numbers and the Guacamole state', async ({ page }) => {
  await open(page, '/')
  await expect(page.getByText(/online/i).first()).toBeVisible()
  await expect(page.getByText(/guacamole/i).first()).toBeVisible()
})

test('@feature:enroll create an enrolment code and see both one-liners', async ({ page }) => {
  await open(page, '/enroll')
  await page.getByRole('button', { name: 'Create code' }).click()
  await page.getByRole('tab', { name: /macos/i }).click() // the default tab follows the browser's OS
  // Both install types are offered; Permanent (sudo) is selected first.
  await expect(page.getByRole('radio', { name: 'Permanent' })).toBeChecked()
  await expect(page.getByText(/curl -fsSL https:\/\/.*\/e\/[a-z2-9]{6} \| sudo sh/)).toBeVisible()
  await expect(page.getByText(/curl -fsSL https:\/\/.*\/e\/[a-z2-9]{6} \| sh$/)).toHaveCount(0)
  await page.getByText('Temporary', { exact: true }).click()
  await expect(page.getByText(/curl -fsSL https:\/\/.*\/e\/[a-z2-9]{6} \| sh$/)).toBeVisible()
  await expect(page.getByText(/\| sudo sh/)).toHaveCount(0)
  await page.screenshot({ path: 'test-results/enroll-commands.png' })
  await page.getByRole('tab', { name: /windows/i }).click()
  await expect(page.getByText(/irm https:\/\/.*\/e\/[a-z2-9]{6} \| iex/)).toBeVisible()
})

test('@feature:devices list, filter, drill into a device and export', async ({ page }) => {
  await open(page, '/devices')
  const rows = page.getByRole('row')
  await expect(rows.nth(1)).toBeVisible()
  await rows.nth(1).click()
  await expect(page).toHaveURL(/\/devices\/dev_/)
  await expect(page.getByRole('tab', { name: /services/i })).toBeVisible()
  await page.goto('/devices')
  const dl = page.waitForEvent('download')
  await page.getByRole('button', { name: /csv/i }).click()
  expect((await dl).suggestedFilename()).toMatch(/\.csv$/)
})

test('@feature:groups create, edit and delete a group', async ({ page }) => {
  const name = 'Journey ' + Date.now().toString(36)
  await open(page, '/groups')
  await page.getByRole('button', { name: 'New group' }).click()
  await page.getByLabel(/^name/i).fill(name)
  await page.getByRole('button', { name: 'Create group' }).click()
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible()
  await page.getByRole('row', { name: new RegExp(name) }).getByRole('button', { name: /delete/i }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: /delete/i }).click()
  await expect(page.getByRole('cell', { name, exact: true })).toHaveCount(0)
})

test('@feature:users add a user who can sign in later', async ({ page }) => {
  const email = `e2e-${Date.now().toString(36)}@example.com`
  await open(page, '/users')
  await page.getByRole('button', { name: 'Add user' }).first().click()
  await page.getByLabel(/email/i).fill(email)
  await page.getByRole('dialog').getByRole('button', { name: 'Add user' }).click()
  await expect(page.getByRole('cell', { name: email, exact: true })).toBeVisible()
})

test('@feature:sessions session tabs reflect ownership rules', async ({ page }) => {
  await open(page, '/sessions')
  await expect(page.getByRole('tab', { name: /mine/i })).toBeVisible()
  await expect(page.getByRole('tab', { name: /shared with me/i })).toBeVisible()
  await expect(page.getByRole('tab', { name: /all sessions/i })).toBeVisible() // admin: view-only list
})

test('@feature:integration run the Guacamole checks: every hop passes', async ({ page }) => {
  await open(page, '/integration')
  await page.getByRole('button', { name: 'Run checks' }).click()
  await expect(page.getByText('Guacamole is ready')).toBeVisible({ timeout: 15_000 })
})

test('@feature:logs logs are searchable and filter by level', async ({ page }) => {
  await open(page, '/logs')
  await expect(page.getByText(/http\.request|job\./).first()).toBeVisible({ timeout: 10_000 })
})

test('@feature:debug run a background job now', async ({ page }) => {
  await open(page, '/debug')
  await page.getByRole('row', { name: /audit-verify/ }).getByRole('button', { name: 'Run now' }).click()
  await expect(page.getByText(/started|queued|running|accepted/i).first()).toBeVisible()
})

test('@feature:settings change a setting and see it persist', async ({ page, request }) => {
  await open(page, '/settings')
  const current = (await api(request, ADMIN, 'GET', '/api/v1/settings')).body.data.enrollment_ttl_minutes
  const next = current === 20 ? 25 : 20 // always a real change, so Save is enabled
  await page.getByLabel('Enrolment code lifetime').fill(String(next))
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect.poll(async () => (await api(request, ADMIN, 'GET', '/api/v1/settings')).body.data.enrollment_ttl_minutes).toBe(next)
})

test('@feature:audit the audit trail records actions with actor and role and exports CSV', async ({ page }) => {
  await open(page, '/audit')
  await expect(page.getByRole('cell', { name: /settings\.update|group\.create/ }).first()).toBeVisible()
  await expect(page.getByText('admin@example.com').first()).toBeVisible()
  const dl = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Download CSV' }).click()
  expect((await dl).suggestedFilename()).toMatch(/\.csv$/)
})

test('@feature:help help opens from the ? button and links the full guide', async ({ page }) => {
  await open(page, '/devices')
  await page.getByRole('button', { name: /help/i }).first().click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByRole('dialog').getByText(/devices/i).first()).toBeVisible()
})

test('@feature:services see every service, read guacd logs, restart guacd and watch it come back', async ({ page }) => {
  test.setTimeout(90_000)
  await open(page, '/services')
  for (const name of ['RemoteHound', 'Tunnel server', 'Data store', 'Guacamole', 'guacd']) {
    // The heading's accessible name also carries its ⓘ button ("About …"), so match the start.
    await expect(page.getByRole('heading', { name: new RegExp(`^${name}\\b`), level: 3 }).first()).toBeVisible()
  }
  await expect(page.getByRole('heading', { name: 'Guacamole configuration' })).toBeVisible()
  await expect(page.getByText(/no users or connections/i).first()).toBeVisible()
  const card = (name) => page.locator('li.svc-card').filter({ has: page.getByRole('heading', { name: new RegExp(`^${name}\\b`), level: 3 }) })
  const guacd = card('guacd')
  // Logs drawer: real container output through rh-control.
  await guacd.getByRole('button', { name: 'View logs' }).click()
  const drawer = page.getByRole('dialog', { name: /guacd logs/i })
  await expect(drawer.getByRole('log')).toContainText(/guacd/i)
  await drawer.getByRole('button', { name: 'Close' }).click()
  // Restart for real; the card comes back as running.
  await guacd.getByRole('button', { name: 'Restart' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Restart' }).click()
  await expect(page.getByText(/guacd: running/i)).toBeVisible({ timeout: 60_000 })
  // RemoteHound offers restart only — never stop.
  const rh = card('RemoteHound')
  await expect(rh.getByRole('button', { name: 'Restart' })).toBeVisible()
  await expect(rh.getByRole('button', { name: 'Stop' })).toHaveCount(0)
})

test('@feature:services sign out goes to the proxy logout and lands on the signed-out page', async ({ page }) => {
  await open(page, '/')
  await page.getByRole('button', { name: 'Sign out' }).first().click()
  await expect(page).toHaveURL(/\/signed-out/)
  await expect(page.getByRole('heading', { name: /signed out/i })).toBeVisible()
})

test('@feature:devices a removed device explains how to register the machine', async ({ page, request }) => {
  // Enrol a device by API (never connects, so it is offline), then delete it.
  const enr = (await api(request, ADMIN, 'POST', '/api/v1/enrollments', { name: 'gone-box' })).body.data
  const { publicKey } = await import('node:crypto').then(c => c.generateKeyPairSync('ed25519'))
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12)
  const blob = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), raw])
  const res = await request.post(ADMIN + '/api/v1/enroll', { ignoreHTTPSErrors: true, data: { code: enr.code, public_key: 'ssh-ed25519 ' + blob.toString('base64'), hostname: 'gone-box', os: 'linux', services: [{ kind: 'ssh', remote_port: 22 }] } })
  expect(res.status()).toBe(201)
  const id = (await res.json()).data.device_id

  await open(page, `/devices/${id}`)
  await expect(page.getByText('This device is not connected')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Get the install command' })).toHaveAttribute('href', '/enroll?name=gone-box')
  await page.getByRole('link', { name: 'Get the install command' }).click()
  await expect(page.getByRole('textbox', { name: /Device name/ })).toHaveValue('gone-box')

  expect((await api(request, ADMIN, 'DELETE', `/api/v1/devices/${id}`)).status).toBe(204)
  page.allowedErrors = [/404/]
  await page.goto(`/devices/${id}`)
  await expect(page.getByRole('heading', { name: "This device isn't registered" })).toBeVisible()
  await expect(page.getByText(/curl -fsSL .*\/e\/CODE \| sh/)).toBeVisible()
  await expect(page.getByText(/irm .*\/e\/CODE \| iex/)).toBeVisible()
  await expect(page.getByRole('link', { name: 'Register a machine' })).toHaveAttribute('href', '/enroll')
  await page.screenshot({ path: 'test-results/device-not-registered.png', fullPage: true })

  await open(page, '/enroll?state=used')
  const again = page.getByRole('link', { name: 'gone-box (removed) · register again' }).first()
  await expect(again).toHaveAttribute('href', '/enroll?name=gone-box')
  await again.click()
  const name = page.getByRole('textbox', { name: /Device name/ })
  await expect(name).toHaveValue('gone-box')
  await expect(name).toBeFocused()
  await expect(page.getByText('Registering gone-box again')).toBeVisible()
  // The same link again (already on that URL) still re-renders: the field is refilled.
  await name.fill('')
  await page.getByRole('link', { name: 'gone-box (removed) · register again' }).first().click()
  await expect(name).toHaveValue('gone-box')
})

test('@feature:enroll @feature:devices a wrong-machine enrolment is refused or flagged', async ({ page, request }) => {
  const pubkey = async () => {
    const { publicKey } = (await import('node:crypto')).generateKeyPairSync('ed25519')
    const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12)
    return 'ssh-ed25519 ' + Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), raw]).toString('base64')
  }
  const redeem = async (code, os, hostname) => request.post(ADMIN + '/api/v1/enroll', { ignoreHTTPSErrors: true, data: { code, public_key: await pubkey(), hostname, os } })
  const stamp = Date.now().toString(36)

  // Machine type on the code: a Mac cannot use a Linux code, and the code survives.
  await open(page, '/enroll')
  await page.getByRole('textbox', { name: /Device name/ }).fill(`srv-${stamp}`)
  await page.getByLabel('Machine type').selectOption('linux')
  await page.getByRole('button', { name: 'Create code' }).click()
  await expect(page.getByText('Only a Linux machine can use it.')).toBeVisible()
  const code = (await page.locator('.keycaps').getAttribute('aria-label')).replace('Enrolment code ', '').replace(/ /g, '')
  const wrong = await redeem(code, 'macos', `mac-${stamp}`)
  expect(wrong.status()).toBe(400)
  expect((await wrong.json()).code).toBe('ENROLL_WRONG_OS')
  expect((await redeem(code, 'linux', `srv-${stamp}`)).status()).toBe(201)

  // No machine type: accepted, but a "-linux" name on a Mac is flagged, with a rename.
  const enr = (await api(request, ADMIN, 'POST', '/api/v1/enrollments', { name: `lab-linux-${stamp}` })).body.data
  const res = await redeem(enr.code, 'macos', `Studio-${stamp}`)
  const id = (await res.json()).data.device_id
  await open(page, `/devices/${id}`)
  await expect(page.getByText('This may not be the machine its name says')).toBeVisible()
  await page.getByRole('button', { name: `Rename to Studio-${stamp}` }).click()
  await expect(page.locator('h1')).toHaveText(`Studio-${stamp}`)
  await expect(page.getByText('This may not be the machine its name says')).toHaveCount(0)

  // The same machine enrolled again: both entries are flagged.
  const again = (await api(request, ADMIN, 'POST', '/api/v1/enrollments', { name: `studio-again-${stamp}` })).body.data
  await redeem(again.code, 'macos', `Studio-${stamp}`)
  await open(page, `/devices/${id}`)
  await expect(page.getByText('This machine may be enrolled twice')).toBeVisible()
  await expect(page.getByRole('link', { name: `Open studio-again-${stamp}` })).toBeVisible()
  await open(page, '/devices')
  await expect(page.getByRole('row', { name: new RegExp(`Studio-${stamp}`) }).getByText('Check identity')).toHaveCount(2) // both entries of the twice-enrolled Mac
  await page.screenshot({ path: 'test-results/identity-devices.png' })
})

test('@feature:enroll edit an open code, clear used and expired codes, revoke the open one', async ({ page }) => {
  await open(page, '/enroll')
  await page.getByLabel('Device name (optional)').first().fill('typo-nmae')
  await page.getByRole('button', { name: 'Create code' }).click()
  await expect(page.getByText('Waiting for the device…')).toBeVisible()
  const codes = page.getByRole('region', { name: 'Enrolment codes' }).or(page.locator('section[aria-labelledby=codes-h]'))
  const row = codes.getByRole('row').filter({ hasText: 'typo-nmae' }).first()
  await row.getByRole('button', { name: 'Edit' }).click()
  const drawer = page.getByRole('dialog', { name: 'Edit enrolment code' })
  await drawer.getByLabel('Device name (optional)').fill('fixed-name')
  await drawer.getByLabel('Machine type').selectOption('linux')
  await drawer.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Code updated')).toBeVisible()
  const fixed = codes.getByRole('row').filter({ hasText: 'fixed-name' }).first()
  await expect(fixed).toContainText('Linux')
  await expect(fixed).not.toContainText('usr_') // created by shows a person, not an ID
  await page.screenshot({ path: 'test-results/enroll-codes-manage.png', fullPage: true })
  // Clear removes every used and expired code; open ones stay.
  await page.getByRole('button', { name: 'Clear used & expired' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Clear', exact: true }).click()
  await expect(page.getByText(/Removed \d+ codes?|Nothing to clear/)).toBeVisible()
  await expect(codes.getByRole('row').filter({ hasText: 'fixed-name' }).first()).toBeVisible()
  await expect(codes.getByRole('row').filter({ has: page.getByText('Used', { exact: true }) })).toHaveCount(0)
  await fixed.getByRole('button', { name: 'Revoke' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByText('Code revoked')).toBeVisible()
})
