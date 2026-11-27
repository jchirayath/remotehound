// @kind:e2e
// Main journeys through the real UI against the live bundle (TEST-0 e2e kind).
import { test, expect, open, api, ADMIN, OPERATOR, enrolDevice, sshPublicKey, auditFor } from '../fixtures.mjs'
import { SEED_DEVICE } from '../global-setup.mjs'

test('@feature:overview overview shows live numbers and the Guacamole state', async ({ page }) => {
  await open(page, '/')
  await expect(page.getByText(/online/i).first()).toBeVisible()
  await expect(page.getByText(/guacamole/i).first()).toBeVisible()
})

test('@feature:enroll create an enrollment code and see both one-liners', async ({ page }) => {
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
  await page.getByRole('searchbox', { name: 'Search devices' }).fill(SEED_DEVICE)
  await expect(page).toHaveURL(new RegExp(`q=${SEED_DEVICE}`))
  const row = page.getByRole('row', { name: new RegExp(SEED_DEVICE) })
  await expect(row).toHaveCount(1)
  await page.getByRole('searchbox', { name: 'Search devices' }).fill('no-such-device-zzz')
  await expect(page.getByRole('row', { name: new RegExp(SEED_DEVICE) })).toHaveCount(0)
  await page.getByRole('searchbox', { name: 'Search devices' }).fill(SEED_DEVICE)
  await row.click()
  await expect(page).toHaveURL(/\/devices\/dev_/)
  await expect(page.getByRole('tab', { name: /services/i })).toBeVisible()
  await page.goto('/devices')
  const dl = page.waitForEvent('download')
  await page.getByRole('button', { name: /csv/i }).click()
  expect((await dl).suggestedFilename()).toMatch(/\.csv$/)
})

test('@feature:devices edit, disable, enable and delete a device; each change audited once', async ({ page, request }) => {
  const stamp = Date.now().toString(36)
  const id = await enrolDevice(request, { name: `crud-${stamp}` })
  await open(page, `/devices/${id}`)

  // Edit name, tags and notes on the Overview tab.
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill(`crud-renamed-${stamp}`)
  await page.getByRole('textbox', { name: 'Tags' }).fill('kiosk, floor-2')
  await page.getByRole('textbox', { name: 'Notes' }).fill('Front desk')
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Device saved')).toBeVisible()
  await expect(page.locator('h1')).toHaveText(`crud-renamed-${stamp}`)
  await expect(page).toHaveTitle(`crud-renamed-${stamp} · RemoteHound`) // the browser tab follows the rename
  const saved = (await api(request, ADMIN, 'GET', `/api/v1/devices/${id}`)).body.data
  expect(saved.tags).toEqual(['kiosk', 'floor-2'])
  expect(saved.notes).toBe('Front desk')

  // Disable (confirmed), then enable.
  await page.getByRole('button', { name: 'Disable', exact: true }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Disable' }).click()
  await expect(page.getByText('Device disabled')).toBeVisible()
  await expect.poll(async () => (await api(request, ADMIN, 'GET', `/api/v1/devices/${id}`)).body.data.status).toBe('disabled')
  await page.getByRole('button', { name: 'Enable', exact: true }).click()
  await expect(page.getByText('Device enabled')).toBeVisible()

  // Delete needs the name typed; Delete stays disabled until it matches.
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  const dlg = page.getByRole('alertdialog')
  await expect(dlg.getByRole('button', { name: 'Delete device' })).toBeDisabled()
  await dlg.getByRole('textbox').fill(`crud-renamed-${stamp}`)
  await dlg.getByRole('button', { name: 'Delete device' }).click()
  await expect(page).toHaveURL(/\/devices$/)
  expect((await api(request, ADMIN, 'GET', `/api/v1/devices/${id}`)).status).toBe(404)

  const res = `device:${id}`
  expect(await auditFor(request, 'device.update', res)).toHaveLength(1)
  expect(await auditFor(request, 'device.disable', res)).toHaveLength(1)
  expect(await auditFor(request, 'device.enable', res)).toHaveLength(1)
  expect(await auditFor(request, 'device.delete', res)).toHaveLength(1)
})

test('@feature:groups create, edit and delete a group; each change audited once', async ({ page, request }) => {
  const name = 'Journey ' + Date.now().toString(36)
  await open(page, '/groups')
  await page.getByRole('button', { name: 'New group' }).click()
  await page.getByLabel(/^name/i).fill(name)
  await page.getByRole('button', { name: 'Create group' }).click()
  await expect(page.getByText(`Group ${name} created`)).toBeVisible()
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible()
  const id = (await api(request, ADMIN, 'GET', '/api/v1/groups')).body.data.find(g => g.name === name).id

  // Edit: rename, describe, recolor.
  await page.getByRole('button', { name: `Edit ${name}` }).click()
  const drawer = page.getByRole('dialog', { name: `Edit ${name}` })
  await drawer.getByLabel(/^name/i).fill(`${name} v2`)
  await drawer.getByLabel('Description').fill('Second floor')
  await drawer.getByText('rose', { exact: true }).click()
  await drawer.getByRole('button', { name: 'Save group' }).click()
  await expect(page.getByText(`Group ${name} v2 saved`)).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Second floor' })).toBeVisible()
  const after = (await api(request, ADMIN, 'GET', `/api/v1/groups/${id}`)).body.data
  expect([after.name, after.description, after.color]).toEqual([`${name} v2`, 'Second floor', 'rose'])

  await page.getByRole('button', { name: `Delete ${name} v2` }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: /delete/i }).click()
  await expect(page.getByRole('cell', { name: `${name} v2`, exact: true })).toHaveCount(0)

  for (const ev of ['group.create', 'group.update', 'group.delete']) expect(await auditFor(request, ev, `group:${id}`), ev).toHaveLength(1)
})

test('@feature:users add, edit, block and delete a user; each change audited once', async ({ page, request }) => {
  const email = `e2e-${Date.now().toString(36)}@example.com`
  await open(page, '/users')
  await page.getByRole('button', { name: 'Add user' }).first().click()
  await page.getByLabel(/email/i).fill(email)
  await page.getByRole('dialog').getByRole('button', { name: 'Add user' }).click()
  await expect(page.getByRole('cell', { name: email, exact: true })).toBeVisible()
  const id = (await api(request, ADMIN, 'GET', `/api/v1/users?q=${encodeURIComponent(email)}`)).body.data[0].id

  // Edit: name, role, a group, and block sign-in.
  await page.getByRole('button', { name: `Edit ${email}` }).click()
  const drawer = page.getByRole('dialog')
  await drawer.getByLabel('Display name').fill('Journey Person')
  await drawer.getByLabel('Role').selectOption('operator')
  await drawer.getByLabel(/E2E/).check()
  await drawer.getByText('Block sign-in', { exact: true }).click() // the switch's visible label, as a person clicks it
  await expect(drawer.getByRole('switch', { name: 'Block sign-in' })).toBeChecked()
  await drawer.getByRole('button', { name: 'Save user' }).click()
  await expect(page.getByText('User saved')).toBeVisible()
  const row = page.getByRole('row', { name: new RegExp(email) })
  await expect(row.getByText('Blocked')).toBeVisible()
  await expect(row.getByText('operator')).toBeVisible()
  const u = (await api(request, ADMIN, 'GET', `/api/v1/users/${id}`)).body.data
  expect([u.display_name, u.role, u.disabled, u.group_ids.length]).toEqual(['Journey Person', 'operator', true, 1])

  // The signed-in admin cannot delete themselves: no delete button on their own row.
  await expect(page.getByRole('button', { name: 'Delete admin@example.com' })).toHaveCount(0)

  await page.getByRole('button', { name: `Delete ${email}` }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete user' }).click()
  await expect(page.getByText('User deleted')).toBeVisible()
  await expect(page.getByRole('cell', { name: email, exact: true })).toHaveCount(0)

  for (const ev of ['user.create', 'user.update', 'user.delete']) expect(await auditFor(request, ev, `user:${id}`), ev).toHaveLength(1)
})

test('@feature:help save, edit and delete my own login for a device', async ({ page, request }) => {
  const dev = (await api(request, ADMIN, 'GET', `/api/v1/devices?q=${SEED_DEVICE}`)).body.data.find(d => d.name === SEED_DEVICE)
  await open(page, '/profile')
  await page.getByRole('button', { name: 'Save a login' }).click()
  const drawer = page.getByRole('dialog', { name: 'Save my own login' })
  await drawer.getByLabel('Device').selectOption({ label: SEED_DEVICE })
  await drawer.getByLabel('Service').selectOption('ssh')
  await drawer.getByLabel('Username').fill('e2e-user')
  await drawer.getByLabel('Password').fill('e2e-dummy-pass') // gitleaks:allow (fixture against a throwaway test bundle)
  await drawer.getByRole('button', { name: 'Save login' }).click()
  await expect(page.getByText('Login saved')).toBeVisible()
  const row = page.getByRole('row', { name: new RegExp(SEED_DEVICE) })
  await expect(row.getByText('e2e-user')).toBeVisible()
  // The API never returns the secret.
  const listed = (await api(request, ADMIN, 'GET', '/api/v1/me/credentials')).body.data.find(c => c.device_id === dev.id)
  expect(JSON.stringify(listed)).not.toContain('e2e-dummy-pass')

  // Edit: username changes only when the password is typed again.
  await row.getByRole('button', { name: 'Edit' }).click()
  const edit = page.getByRole('dialog', { name: new RegExp(`Edit my login · ${SEED_DEVICE}`) })
  await edit.getByLabel('Username').fill('e2e-user2')
  await edit.getByRole('button', { name: 'Save login' }).click()
  await expect(edit.getByText(/Enter the password/)).toBeVisible()
  await edit.getByLabel('Password').fill('e2e-dummy-pass2') // gitleaks:allow
  await edit.getByRole('button', { name: 'Save login' }).click()
  await expect(row.getByText('e2e-user2')).toBeVisible()

  await row.getByRole('button', { name: 'Edit' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('Saved login deleted')).toBeVisible()
  await expect(page.getByRole('row', { name: new RegExp(SEED_DEVICE) })).toHaveCount(0)

  expect((await auditFor(request, 'credential.save', `device:${dev.id}`)).length).toBeGreaterThanOrEqual(2)
  expect((await auditFor(request, 'credential.delete', `device:${dev.id}`)).length).toBeGreaterThanOrEqual(1)
})

test('@feature:help @feature:devices devices that share a name can be told apart when saving a login', async ({ page, request }) => {
  // One machine enrolled twice shows up as two devices with the same name.
  const name = `twin-${Date.now().toString(36)}`
  const a = await enrolDevice(request, { name })
  const b = await enrolDevice(request, { name })
  await open(page, '/profile')
  await page.getByRole('button', { name: 'Save a login' }).click()
  const select = page.getByRole('dialog', { name: 'Save my own login' }).getByLabel('Device')
  await expect(select.locator(`option[value="${a}"]`)).toHaveCount(1)
  const labelA = await select.locator(`option[value="${a}"]`).textContent()
  const labelB = await select.locator(`option[value="${b}"]`).textContent()
  expect(labelA).toMatch(new RegExp(`^${name} · .+ · offline$`))
  expect(labelB).toMatch(new RegExp(`^${name} · .+ · offline$`))
  expect(labelA).not.toBe(labelB)
  // A device whose name is unique keeps its plain name.
  await expect(select.locator('option', { hasText: new RegExp(`^${SEED_DEVICE}$`) })).toHaveCount(1)
  for (const id of [a, b]) expect((await api(request, ADMIN, 'DELETE', `/api/v1/devices/${id}`)).status).toBe(204)
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
  // Stock Guacamole does not report its version: no meaningless "Guacamole unknown".
  await expect(page.getByText(/Guacamole\s+unknown/)).toHaveCount(0)
})

test('@feature:logs logs are searchable, filter by level and follow one request ID', async ({ page, request }) => {
  // A denied request writes WARN records (authz.denied, http.denied) under one request ID.
  const denied = await request.get(OPERATOR + '/api/v1/settings', { ignoreHTTPSErrors: true })
  expect(denied.status()).toBe(403)
  const rid = denied.headers()['x-request-id']
  expect(rid).toBeTruthy()

  await open(page, '/logs')
  await expect(page.getByText(/http\.request|job\./).first()).toBeVisible({ timeout: 10_000 })
  const records = page.getByRole('row').filter({ has: page.getByRole('cell') })

  await page.getByRole('combobox', { name: 'Level' }).selectOption('WARN')
  await expect(page).toHaveURL(/level=WARN/)
  await expect(records.first()).toBeVisible()
  await expect(records.filter({ hasText: /\bINFO\b/ })).toHaveCount(0)

  await page.getByRole('searchbox', { name: 'Search' }).fill('authz.denied')
  await expect(page).toHaveURL(/q=authz\.denied/)
  await expect(records.filter({ hasText: 'authz.denied' }).first()).toBeVisible()
  await expect(records.filter({ hasNotText: 'authz.denied' })).toHaveCount(0)

  // "Show this request only" shows the whole request: the search and level filters are dropped,
  // so the request's other records (http.denied, http.request) appear next to authz.denied.
  await records.filter({ hasText: 'authz.denied' }).first().getByRole('button', { name: 'Show details' }).click()
  await page.getByRole('button', { name: 'Show this request only' }).click()
  await expect(page).toHaveURL(/request_id=/)
  await expect(page).not.toHaveURL(/[?&](q|level)=/)
  await expect(page.getByRole('searchbox', { name: 'Search' })).toHaveValue('')
  await expect(page.getByRole('combobox', { name: 'Level' })).toHaveValue('')
  await expect(records.filter({ hasText: 'http.denied' }).first()).toBeVisible()

  // Request ID: every record of the denied request, and nothing else.
  await page.goto(`/logs?request_id=${rid}`)
  await expect(records.first()).toBeVisible()
  const events = await records.locator('td.mono').allTextContents()
  expect(events.join(' ')).toMatch(/authz\.denied/)
  expect(events.join(' ')).toMatch(/http\.denied/)
})

test('@feature:debug run a background job now and change the log level', async ({ page, request }) => {
  const before = (await api(request, ADMIN, 'GET', '/api/v1/jobs')).body.data.find(j => j.name === 'audit-verify').last_run_at
  await open(page, '/debug')
  await page.getByRole('row', { name: /audit-verify/ }).getByRole('button', { name: 'Run now' }).click()
  await expect(page.getByText('audit-verify started')).toBeVisible()
  await expect.poll(async () => (await api(request, ADMIN, 'GET', '/api/v1/jobs')).body.data.find(j => j.name === 'audit-verify').last_run_at, { timeout: 15_000 }).not.toBe(before)

  const level = page.getByRole('radiogroup', { name: 'Server log level' })
  await level.getByText('DEBUG', { exact: true }).click()
  await expect(page.getByText('Log level set to DEBUG')).toBeVisible()
  await expect.poll(async () => (await api(request, ADMIN, 'GET', '/api/v1/debug/runtime')).body.data.log_level).toBe('DEBUG')
  await level.getByText('INFO', { exact: true }).click()
  await expect(page.getByText('Log level set to INFO')).toBeVisible()
  await expect.poll(async () => (await api(request, ADMIN, 'GET', '/api/v1/debug/runtime')).body.data.log_level).toBe('INFO')
})

test('@feature:settings change a setting and see it persist', async ({ page, request }) => {
  await open(page, '/settings')
  const current = (await api(request, ADMIN, 'GET', '/api/v1/settings')).body.data.enrollment_ttl_minutes
  const next = current === 20 ? 25 : 20 // always a real change, so Save is enabled
  await page.getByLabel('Enrollment code lifetime').fill(String(next))
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

test('@feature:services see every service, read guacd logs, restart guacd and watch it come back', async ({ page, request }) => {
  test.setTimeout(90_000)
  // On a Linux host (CI) the browser shares the machine with Docker: restarting guacd removes its
  // network interface, and Chrome drops the in-flight request as ERR_NETWORK_CHANGED. The restart
  // itself still has to work — the card must come back as running below.
  page.allowedErrors = [/ERR_NETWORK_CHANGED/]
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
  // The 15 s background refresh replaces every card; a keyboard user keeps focus on the same control.
  const logsBtn = guacd.getByRole('button', { name: 'View logs' })
  await logsBtn.focus()
  const before = await logsBtn.elementHandle()
  await expect.poll(() => before.evaluate(el => !el.isConnected), { timeout: 25_000 }).toBe(true)
  await expect.poll(() => page.evaluate(() => document.activeElement?.dataset?.focus)).toBe('guacd:logs')
  // Restart for real: the audit gains exactly one successful restart and the card comes back as
  // running. (Not the "guacd: running" toast — on a Linux host the browser may lose that reply, above.)
  const outcomes = async (ok) => (await auditFor(request, 'service.action', 'service:guacd')).filter(e => (e.outcome === 'success') === ok).length
  const [okBefore, badBefore] = [await outcomes(true), await outcomes(false)]
  await guacd.getByRole('button', { name: 'Restart' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Restart' }).click()
  await expect.poll(() => outcomes(true), { timeout: 60_000 }).toBe(okBefore + 1)
  expect(await outcomes(false), 'the restart was audited as a failure').toBe(badBefore)
  // Even when the browser lost the reply (Linux CI), the console must not claim the restart failed.
  await expect(page.getByText(/guacd: running/i)).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Restart failed')).toHaveCount(0)
  await page.reload()
  // The container state chip (the card's own badge may read "Degraded" while guacd's health check warms up).
  await expect(card('guacd').getByText('running', { exact: true }).first()).toBeVisible({ timeout: 60_000 })
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
  // Enroll a device by API (never connects, so it is offline), then delete it.
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

test('@feature:enroll @feature:devices a wrong-machine enrollment is refused or flagged', async ({ page, request }) => {
  const redeem = async (code, os, hostname) => request.post(ADMIN + '/api/v1/enroll', { ignoreHTTPSErrors: true, data: { code, public_key: await sshPublicKey(), hostname, os } })
  const stamp = Date.now().toString(36)

  // Machine type on the code: a Mac cannot use a Linux code, and the code survives.
  await open(page, '/enroll')
  await page.getByRole('textbox', { name: /Device name/ }).fill(`srv-${stamp}`)
  await page.getByLabel('Machine type').selectOption('linux')
  await page.getByRole('button', { name: 'Create code' }).click()
  await expect(page.getByText('Only a Linux machine can use it.')).toBeVisible()
  const code = (await page.locator('.keycaps').getAttribute('aria-label')).replace('Enrollment code ', '').replace(/ /g, '')
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
  const codes = page.getByRole('region', { name: 'Enrollment codes' }).or(page.locator('section[aria-labeledby=codes-h]'))
  const row = codes.getByRole('row').filter({ hasText: 'typo-nmae' }).first()
  await row.getByRole('button', { name: 'Edit' }).click()
  const drawer = page.getByRole('dialog', { name: 'Edit enrollment code' })
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
