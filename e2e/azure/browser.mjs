// Browser checks for the Azure e2e suite (e2e/azure/run.sh), against the bundle
// through the SSH tunnel. Each check prints PASS/FAIL; any FAIL exits 1.
//
//   node azure/browser.mjs <base_url> <out_dir> <live_rdp_device> <live_ssh_device> <ended_device>
//
// @kind:e2e
// @feature:enroll @feature:devices @feature:sessions
import { chromium } from '@playwright/test'

const [base, outDir, rdpDev, sshDev, endedDev] = process.argv.slice(2)
const say = (s) => process.stdout.write(s + '\n')
let failed = 0
const check = async (what, fn) => {
  try { await fn(); say(`PASS ${what}`) } catch (e) { failed++; say(`FAIL ${what}: ${String(e.message || e).split('\n')[0]}`) }
}

const browser = await chromium.launch({ channel: 'chrome' })
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 720 } })
const page = await ctx.newPage()
const errors = []
page.on('pageerror', (e) => errors.push(e.message))

async function deviceJSON(id) {
  return (await (await page.request.get(`${base}/api/v1/devices/${id}`)).json()).data
}

for (const [id, kind] of [[rdpDev, 'RDP'], [sshDev, 'SSH']]) {
  const d = await deviceJSON(id)
  await check(`${d.name}: device page shows connection code ${d.connection_code}`, async () => {
    await page.goto(`${base}/devices/${id}`)
    await page.getByText(`Connection code ${d.connection_code}`).first().waitFor({ timeout: 15000 })
    await page.screenshot({ path: `${outDir}/${kind}-device.png` })
  })
  await check(`${d.name}: Run probe shows results in view and a summary`, async () => {
    await page.goto(`${base}/devices/${id}?tab=diagnostics`)
    await page.getByRole('button', { name: 'Run probe' }).click()
    await page.getByText(/Probe finished: \d+ reachable/).waitFor({ timeout: 20000 })
    await page.locator('.probe').getByText(/Reachable|Failed/).first().waitFor({ timeout: 5000 }) // result rows rendered
    await page.waitForFunction(() => { // results scrolled into the viewport
      const el = document.querySelector('.probe')
      const r = el && el.getBoundingClientRect()
      return r && r.top < window.innerHeight && r.bottom > 0
    }, null, { timeout: 5000 })
    await page.screenshot({ path: `${outDir}/${kind}-probe.png` })
  })
  await check(`${d.name}: Connect ${kind} opens a Guacamole session that draws`, async () => {
    await page.goto(`${base}/devices/${id}`)
    const [tab] = await Promise.all([ctx.waitForEvent('page'), page.getByRole('button', { name: new RegExp(`Connect ${kind}`) }).first().click()])
    await tab.waitForFunction(() => { // Guacamole's display canvas has real content
      const c = [...document.querySelectorAll('canvas')].find(x => x.width > 200 && x.height > 200)
      if (!c) return false
      const px = c.getContext('2d').getImageData(0, 0, c.width, c.height).data
      for (let i = 0; i < px.length; i += 4000) if (px[i] || px[i + 1] || px[i + 2]) return true
      return false
    }, null, { timeout: 60000, polling: 1000 })
    await tab.screenshot({ path: `${outDir}/${kind}-session.png` })
    await tab.close()
  })
}

await check('ended one-time device shows the "session has ended" banner', async () => {
  await page.goto(`${base}/devices/${endedDev}`)
  await page.getByText('This one-time session has ended').waitFor({ timeout: 15000 })
  await page.screenshot({ path: `${outDir}/ended-device.png` })
})
await check('no uncaught page errors', async () => { if (errors.length) throw new Error(errors.join('; ')) })

await browser.close()
process.exit(failed ? 1 : 0)
