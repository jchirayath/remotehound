/**
 * Help registry access and the help panel (CORE-16, §6G).
 *
 * Contract
 *  - `loadHelp()` fetches /ui/help/registry.json once (through api.js). Call before rendering screens.
 *  - Lookups never throw; missing keys return '' / null so a typo shows as missing help, not a crash.
 *      screenHelp(key)         → screen entry {title, purpose, how_to[], fields{}, columns{}, roles, tips[], troubleshooting[], doc}
 *      fieldHelp('screen.field') → helper text under an input
 *      columnHelp(screen, col) → ⓘ text for a grid column / metric
 *      emptyHelp(key)          → {title, body, action?:{label, href, permission?}}
 *      errorHelp(code)         → {title, fix, doc?}  (HELP-3)
 *  - `openHelp(key)` opens the slide-over panel for a screen; the `?` key and the page chrome's ?
 *    button both call it. The panel can load the full user doc (/docs/<page>.md) in place.
 *  - `searchHelp(q)` → ranked [{key, title, snippet, kind}] for the command palette (HELP-8).
 *  - Emits `help.open` / `help.search` log events without PII (HELP-9).
 */
import { api } from './api.js'
import { h, replace } from './dom.js'
import { icon } from './icons.js'
import { render as renderMd } from './markdown.js'
import { drawer } from './overlay.js'
import { log } from './log.js'

let registry = { screens: {}, fields: {}, empty: {}, errors: {} }
let currentKey = 'overview'

/** Replace the registry (used by tests and by loadHelp). */
export function setRegistry(r) { registry = { screens: {}, fields: {}, empty: {}, errors: {}, ...r } }

export async function loadHelp() {
  const r = await api.get('/ui/help/registry.json')
  setRegistry(r.data)
}

/** The screen the user is looking at — `?` opens help for it. */
export function setCurrentHelp(key) { currentKey = key }

export const screenHelp = (key) => registry.screens[key] || null
export const fieldHelp = (key) => registry.fields[key] || ''
export const columnHelp = (screen, col) => registry.screens[screen]?.columns?.[col] || ''
export const emptyHelp = (key) => registry.empty[key] || null
export function errorHelp(code) {
  return registry.errors[code] || registry.errors[codeFamily(code)] || null
}
function codeFamily(code) {
  if (code === 'NETWORK_OFFLINE' || code === 'TIMEOUT') return 'NETWORK_OFFLINE'
  const byStatus = { HTTP_403: 'AUTH_FORBIDDEN', HTTP_404: 'NOT_FOUND', HTTP_412: 'PRECONDITION_FAILED', HTTP_429: 'RATE_LIMITED' }
  if (byStatus[code]) return byStatus[code]
  if (/_NOT_FOUND$/.test(code)) return 'NOT_FOUND'
  if (/^HTTP_4/.test(code)) return 'VALIDATION_FAILED'
  return 'INTERNAL'
}

/** Doc page id from a doc link ('/docs/devices' → 'devices'). */
export const docPage = (doc) => String(doc || '').replace(/^\/docs\//, '').replace(/\.md$/, '').replace(/[^\w-]/g, '')

/**
 * Search screens, fields and error help.
 * @param {string} q
 * @returns {Array<{kind:'screen'|'field'|'error', key:string, title:string, snippet:string, score:number}>}
 */
export function searchHelp(q) {
  const terms = String(q || '').toLowerCase().split(/\s+/).filter(Boolean)
  if (!terms.length) return []
  const out = []
  const score = (text, weight) => terms.reduce((s, t) => s + (text.toLowerCase().includes(t) ? weight : 0), 0)
  for (const [key, s] of Object.entries(registry.screens)) {
    const body = [s.purpose, ...(s.how_to || []), ...(s.tips || []), ...Object.values(s.fields || {}), ...Object.values(s.columns || {}),
      ...(s.troubleshooting || []).map(t => `${t.problem} ${t.fix}`)].join(' ')
    const sc = score(s.title, 5) + score(body, 1)
    if (sc) out.push({ kind: 'screen', key, title: s.title, snippet: s.purpose, score: sc + 2 })
  }
  for (const [key, text] of Object.entries(registry.fields)) {
    const sc = score(key.replace(/[._]/g, ' '), 2) + score(text, 1)
    if (sc >= terms.length) out.push({ kind: 'field', key, title: key.split('.').slice(1).join(' ').replace(/_/g, ' '), snippet: text, score: sc })
  }
  for (const [code, e] of Object.entries(registry.errors)) {
    const sc = score(code.replace(/_/g, ' '), 3) + score(`${e.title} ${e.fix}`, 1)
    if (sc) out.push({ kind: 'error', key: code, title: e.title, snippet: e.fix, score: sc })
  }
  log.info('help.search', { terms: terms.length, results: out.length })
  return out.sort((a, b) => b.score - a.score).slice(0, 12)
}

let openPanel = null

/** Open the full user guide for a doc link ('/docs/devices') inside the help panel. */
export function openDoc(doc) {
  const page = docPage(doc)
  const key = Object.keys(registry.screens).find(k => docPage(registry.screens[k].doc) === page)
  if (key) openHelp(key, { doc: true })
  else openHelp(currentKey, { doc: true, entry: { title: page.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase()), purpose: '', doc: `/docs/${page}` } })
}

/**
 * Open the help panel for a screen key (defaults to the current screen).
 * @param {string} [key]
 * @param {{doc?: boolean, anchor?: string, entry?: object}} [opts] doc: jump straight to the full guide;
 *   entry: show this ad-hoc entry (e.g. the error-code page) instead of a screen's
 */
export function openHelp(key = currentKey, opts = {}) {
  const entry = opts.entry || screenHelp(key) || screenHelp('overview')
  if (!entry) return
  log.info('help.open', { screen: key })
  if (openPanel) openPanel.close()
  const content = h('div', { class: 'help' })
  const panel = drawer({
    title: entry.title,
    content,
    className: 'drawer--help',
    onClose: () => { if (openPanel === panel) openPanel = null },
  })
  openPanel = panel
  if (opts.doc) showDoc(content, entry, panel)
  else showSummary(content, entry, panel, opts.anchor)
}

function section(title, ...children) {
  return h('section', { class: 'help__section' }, h('h3', { class: 'help__h' }, title), ...children)
}

function showSummary(content, e, panel, anchor) {
  const fields = Object.entries({ ...(e.fields || {}), ...(e.columns || {}) })
  replace(content,
    h('p', { class: 'help__purpose' }, e.purpose),
    e.how_to?.length ? section('How to', h('ol', { class: 'help__steps' }, e.how_to.map(s => h('li', null, renderMd(s))))) : null,
    fields.length ? section('Fields and columns', h('dl', { class: 'help__dl' }, fields.map(([k, v]) => [
      h('dt', { id: `help-f-${k}` }, k.replace(/_/g, ' ')), h('dd', null, v)]))) : null,
    e.roles ? section('Who can do what', h('p', null, e.roles)) : null,
    e.tips?.length ? section('Tips', h('ul', { class: 'help__tips' }, e.tips.map(t => h('li', null, renderMd(t))))) : null,
    e.troubleshooting?.length ? section('Troubleshooting', h('dl', { class: 'help__dl help__dl--trouble' }, e.troubleshooting.map(t => [
      h('dt', null, t.problem), h('dd', null, renderMd(t.fix))]))) : null,
    e.doc ? h('div', { class: 'help__footer' },
      h('button', { type: 'button', class: 'btn btn--secondary', onClick: () => showDoc(content, e, panel) },
        icon('object.document'), 'Read the full guide'),
      h('a', { class: 'btn btn--ghost', href: `${e.doc}.md`, target: '_blank', rel: 'noopener' }, icon('domain.action.open'), 'Open as page')) : null,
  )
  if (anchor) content.querySelector(`#help-f-${CSS.escape(anchor)}`)?.scrollIntoView({ block: 'center' })
}

async function showDoc(content, e, panel) {
  const back = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', onClick: () => showSummary(content, e, panel) }, icon('action.back', { size: 'sm' }), 'Back to summary')
  const body = h('div', { class: 'md', 'aria-busy': 'true' }, h('div', { class: 'skeleton skeleton--text' }), h('div', { class: 'skeleton skeleton--text' }), h('div', { class: 'skeleton skeleton--text skeleton--short' }))
  replace(content, back, body)
  const page = docPage(e.doc)
  try {
    const md = await api.text(`/docs/${page}.md`)
    body.removeAttribute('aria-busy')
    replace(body, renderMd(md, {
      headingOffset: 1,
      onLink: (href, ev) => {
        if (!href.startsWith('/docs/')) return
        ev.preventDefault()
        const target = docPage(href)
        const next = Object.entries(registry.screens).find(([, s]) => docPage(s.doc) === target)
        if (next) { panel.setTitle(next[1].title); showDoc(content, next[1], panel) }
      },
    }))
  } catch (err) {
    body.removeAttribute('aria-busy')
    replace(body, h('p', { class: 'help__error' }, `The full guide could not be loaded (${err.code || 'error'}). The summary above still applies.`),
      err.requestId ? h('p', { class: 'muted' }, 'Request ID ', h('code', null, err.requestId)) : null)
  }
}
