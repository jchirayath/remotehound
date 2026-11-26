/**
 * Device setup guide data (guide/device-setup.html): the allow-lists and message shape shared by
 * the guide page (guide/guide.js) and the Enroll screen that opens it. Pure functions, no DOM.
 */
export const CODE_RE = /^[a-hjkmnp-z2-9]{6}$/
// The public URL allow-list from CLIENT_PROTOCOL.md §1 (validate.PublicURL on the server).
export const BASE_RE = /^https?:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~/-]*)?$/
export const MSG_READY = 'remotehound-guide-ready'
export const MSG_DATA = 'remotehound-guide'
const OSES = new Set(['macos', 'windows'])

/** Server base URL from an enrolment's Windows command ("irm <base>/e/<code> | iex"), or ''. */
export function baseFromCommand(cmd) {
  const m = /^irm (\S+)\/e\/[a-hjkmnp-z2-9]{6} \| iex$/.exec(String(cmd || ''))
  const base = m ? m[1] : ''
  return BASE_RE.test(base) ? base : ''
}

/**
 * Checks a message from the Enroll screen. Returns the clean values, or null when the code is
 * missing or malformed (the guide then stays blank). A bad base, os or name is dropped, not trusted.
 */
export function cleanGuideData(d) {
  if (!d || typeof d !== 'object' || d.type !== MSG_DATA) return null
  const code = String(d.code || '')
  if (!CODE_RE.test(code)) return null
  const base = BASE_RE.test(String(d.base || '')) ? String(d.base).replace(/\/+$/, '') : ''
  const os = OSES.has(d.os) ? d.os : ''
  const name = String(d.name || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 64)
  const expires = typeof d.expires_at === 'string' ? d.expires_at : ''
  return { code, base, os, name, expires }
}

/**
 * The base for a page with no message: the origin serving it, never anything from the URL, so
 * nobody can link to this page on a real server with someone else's address in the commands.
 */
export function initialBase(loc) {
  return BASE_RE.test(loc.origin) ? loc.origin : ''
}
