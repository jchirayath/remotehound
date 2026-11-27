/**
 * Device setup guide (device-setup.html): fills the printable guide in for one enrollment code.
 *
 * Where the values come from, most trusted first:
 *  - The Enroll screen that opened this tab sends {type: 'remotehound-guide', code, base, os, name,
 *    expires_at} by postMessage, after this page says it is ready. Only a message from this page's
 *    own origin AND from the window that opened it is read. The code therefore never appears in a
 *    URL, the browser history or a server log.
 *  - Otherwise this server's own origin, and the code stays blank to be written in by hand.
 *    Nothing is read from the URL. (The website PDF, website/guide-pdf.sh, prints a copy with the
 *    address written into the HTML; modules don't run from file://, so this script doesn't either.)
 * Every value is checked against the same allow-lists the server uses and written with
 * textContent only.
 */
import { absoluteTime } from '../lib/format.js'
import { log } from '../lib/log.js'

import { cleanGuideData, initialBase, MSG_READY } from '../lib/guide-data.js'

function setAll(sel, text) {
  for (const el of document.querySelectorAll(sel)) el.textContent = text
}

function fill(v) {
  const root = document.documentElement
  if (v.base) setAll('[data-fill="base"]', v.base)
  if (!v.code) { root.dataset.state = 'blank'; return }
  setAll('[data-fill="code"]', v.code)
  setAll('[data-fill="code-ex"]', v.code)
  const slots = document.querySelectorAll('[data-fill="slots"] span')
  v.code.split('').forEach((c, i) => { if (slots[i]) slots[i].textContent = c })
  if (v.name) setAll('[data-fill="name"]', v.name)
  if (v.expires) setAll('[data-fill="expires"]', absoluteTime(v.expires))
  setAll('[data-fill="what"]', v.os === 'macos' ? 'this Mac' : v.os === 'windows' ? 'this Windows PC' : 'this computer')
  if (v.os) root.dataset.os = v.os
  root.dataset.state = 'filled'
  document.title = `Connect ${v.name || 'a computer'} to RemoteHound`
}

function boot() {
  const base = initialBase(location)
  fill({ base, code: '' })
  for (const b of document.querySelectorAll('[data-action="print"]')) b.addEventListener('click', () => window.print())
  const opener = window.opener
  if (!opener || location.protocol === 'file:') return
  document.documentElement.dataset.state = 'waiting'
  const giveUp = setTimeout(() => { document.documentElement.dataset.state = 'blank' }, 5000)
  window.addEventListener('message', function onMsg(ev) {
    if (ev.origin !== location.origin || ev.source !== opener) return
    const v = cleanGuideData(ev.data)
    if (!v) return
    clearTimeout(giveUp)
    window.removeEventListener('message', onMsg)
    fill({ ...v, base: v.base || base })
  })
  try { opener.postMessage({ type: MSG_READY }, location.origin) } catch (err) {
    log.warn('guide.opener_unreachable', { reason: String(err?.name || 'error') }) // stays blank after the timeout
  }
}

if (typeof document !== 'undefined') boot()
