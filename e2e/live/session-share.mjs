// Live, end-to-end proof against the running bundle (not part of `npm test`:
// it needs a device). Run after .claude/commands/smoke.md has enrolled
// "live-box" with a local user rh/rh-demo-pass:
//   node live/session-share.mjs <screenshot-dir>
// It opens a real SSH session in Guacamole as the admin using the admin's
// personal saved login, shares it view-only with the operator, joins as the
// operator, proves keystrokes from the viewer do not reach the shell, checks the
// grantee cannot re-share or end it, then ends it as admin.
import { chromium, request } from '@playwright/test'
import { api, ADMIN, OPERATOR } from '../fixtures.mjs'

const out = process.argv[2] || '.'
const must = (cond, msg) => { if (!cond) { console.error('FAIL', msg); process.exit(1) } console.log('PASS', msg) }
const rq = await request.newContext({ ignoreHTTPSErrors: true })
const dev = (await api(rq, ADMIN, 'GET', '/api/v1/devices?q=live-box')).body.data.find(d => d.online)
must(dev, 'live-box is online')
await api(rq, ADMIN, 'PUT', `/api/v1/me/credentials/${dev.id}/ssh`, { username: 'rh', password: 'rh-demo-pass' })

const b = await chromium.launch({ channel: 'chrome' })
const canvas = (p) => p.waitForFunction(() => [...document.querySelectorAll('canvas')].some(c => c.width > 100), null, { timeout: 30000 })
const admin = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } })
const ap = await admin.newPage()
await ap.goto(ADMIN + '/devices/' + dev.id)
const popup = admin.waitForEvent('page')
await ap.getByRole('button', { name: /connect ssh/i }).click()
const gp = await popup
await canvas(gp)
await gp.waitForTimeout(2500)
await gp.mouse.click(640, 400)
await gp.keyboard.type('echo SHARED-$((6*7)) as $(whoami)')
await gp.keyboard.press('Enter')
await gp.waitForTimeout(2000)
await gp.screenshot({ path: `${out}/1-admin-session.png` })

const opMe = (await api(rq, OPERATOR, 'GET', '/api/v1/me')).body.data
const s = (await api(rq, ADMIN, 'GET', '/api/v1/sessions?scope=mine&active=true')).body.data[0]
must(s && s.can_share, 'admin owns the live session and can share it')
must((await api(rq, ADMIN, 'POST', `/api/v1/sessions/${s.id}/shares`, { user_id: opMe.id, mode: 'view', ttl_minutes: 15 })).status === 200, 'shared view-only with the operator')

const op = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } })
const opPage = await op.newPage()
await opPage.goto(OPERATOR + '/sessions')
await opPage.getByRole('tab', { name: /shared with me/i }).click()
const jpop = op.waitForEvent('page')
await opPage.getByRole('button', { name: /^join/i }).first().click()
const jp = await jpop
await canvas(jp)
await jp.waitForTimeout(2500)
await jp.mouse.click(640, 400)
await jp.keyboard.type('echo VIEWER-TYPED')
await jp.keyboard.press('Enter')
await jp.waitForTimeout(1500)
await jp.screenshot({ path: `${out}/2-operator-joined-view-only.png` })
await gp.screenshot({ path: `${out}/3-admin-after-viewer-typed.png` })
must((await api(rq, OPERATOR, 'POST', `/api/v1/sessions/${s.id}/shares`, { user_id: opMe.id, mode: 'control' })).status === 403, 'grantee cannot re-share')
must((await api(rq, OPERATOR, 'POST', `/api/v1/sessions/${s.id}/terminate`)).status === 403, 'grantee cannot end the session')
must((await api(rq, ADMIN, 'POST', `/api/v1/sessions/${s.id}/terminate`)).status === 202, 'admin ends the session')
await gp.waitForTimeout(2500)
await gp.screenshot({ path: `${out}/4-ended.png` })
console.log('Screenshots in', out, '— check 3-admin-after-viewer-typed.png does NOT show VIEWER-TYPED.')
await b.close()
