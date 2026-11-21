/**
 * Theme controller (CORE-13, THEME-6) — the one place the theme mode changes.
 *
 * Contract
 *  - Modes: 'system' | 'light' | 'dark'. 'system' removes <html data-theme> so tokens.css follows
 *    prefers-color-scheme; the others set data-theme.
 *  - First paint: /ui/theme-boot.js applies the cached mode from localStorage 'rh.theme' before CSS
 *    renders (no flash). That cache is a display preference, not a credential.
 *  - `initTheme(serverMode)` reconciles with the per-user value from /api/v1/me.
 *  - `setTheme(mode)` applies immediately, caches locally, and persists per user via
 *    PUT /api/v1/me/preferences (failure keeps the local choice and reports it).
 *  - Fires 'rh:theme' on document with detail {mode, effective}.
 */
import { api } from './api.js'
import { log } from './log.js'

export const MODES = ['system', 'light', 'dark']
const KEY = 'rh.theme'
let mode = 'system'

function cache(m) {
  try { localStorage.setItem(KEY, m) } catch (e) { log.debug('theme.cache_unavailable', { reason: e?.name }) }
}

/** The theme actually showing ('light' | 'dark'). */
export function effectiveTheme() {
  if (mode !== 'system') return mode
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/** Apply a mode to the document (no persistence). */
export function applyTheme(m) {
  mode = MODES.includes(m) ? m : 'system'
  const root = document.documentElement
  if (mode === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', mode)
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', getComputedStyle(root).getPropertyValue('--color-domain-chrome-bg').trim())
  document.dispatchEvent(new CustomEvent('rh:theme', { detail: { mode, effective: effectiveTheme() } }))
}

export const currentTheme = () => mode

/** Reconcile with the server's per-user preference at boot. */
export function initTheme(serverMode) {
  const m = MODES.includes(serverMode) ? serverMode : (document.documentElement.getAttribute('data-theme') || 'system')
  applyTheme(m)
  cache(m)
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (mode === 'system') applyTheme('system') })
}

/**
 * Change the theme at runtime and persist it for this user.
 * @param {'system'|'light'|'dark'} m
 * @returns {Promise<void>} rejects with ApiError if the server could not store it (local choice stays)
 */
export async function setTheme(m) {
  applyTheme(m)
  cache(mode)
  await api.put('/api/v1/me/preferences', { theme: mode })
}
