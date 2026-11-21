/**
 * Client logger (LOG-2, CORE-3 for the browser). The only file allowed to call console.*.
 *
 * Contract:
 *  - log.debug/info/warn/error(event, attrs) — `event` is a dotted event name (e.g. 'help.open'),
 *    `attrs` a flat object of ids and counts. Never pass credentials or user-entered secrets.
 *  - Records are kept in a small in-memory ring (`log.recent()`) so the Debug screen and bug
 *    reports can show what the UI did; debug records only print when localStorage 'rh.debug' = '1'.
 */

const RING = []
const MAX = 200
const SECRET = /pass(word)?|secret|token|authorization|cookie|credential/i

function debugEnabled() {
  try { return globalThis.localStorage?.getItem('rh.debug') === '1' } catch { return false }
}

function scrub(attrs) {
  const out = {}
  for (const [k, v] of Object.entries(attrs || {})) out[k] = SECRET.test(k) ? '[redacted]' : v
  return out
}

function emit(level, event, attrs) {
  const rec = { timestamp: new Date().toISOString(), severity_text: level, 'event.name': event, attributes: scrub(attrs) }
  RING.push(rec)
  if (RING.length > MAX) RING.shift()
  if (level === 'DEBUG' && !debugEnabled()) return
  const fn = level === 'ERROR' ? console.error : level === 'WARN' ? console.warn : level === 'DEBUG' ? console.debug : console.info
  fn('[rh]', event, rec.attributes)
}

export const log = {
  debug: (event, attrs) => emit('DEBUG', event, attrs),
  info: (event, attrs) => emit('INFO', event, attrs),
  warn: (event, attrs) => emit('WARN', event, attrs),
  error: (event, attrs) => emit('ERROR', event, attrs),
  /** @returns {object[]} a copy of the recent records, oldest first */
  recent: () => RING.slice(),
}
