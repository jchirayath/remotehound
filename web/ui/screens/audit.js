/**
 * Audit (/audit) — the append-only, hash-chained record of every state change and privileged read.
 * Data: GET /api/v1/audit (filters event, outcome; cursor paged). "Download CSV" streams the full
 * filtered log from the server (?format=csv); the grid's CSV/JSON buttons export the rows loaded.
 */
import { h, append } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { page, grid, filterSelect, badge, button, relTime, toast, toastError } from '../lib/ui.js'
import { absoluteTime, eventLabel as humanEvent } from '../lib/format.js'

const OUTCOME_TONE = { success: 'success', failure: 'danger', denied: 'warning' }

export default function render(ctx) {
  const q0 = ctx.query || {}
  const filters = { event: q0.event || '', outcome: q0.outcome || '' }
  const p = page({
    title: 'Audit log',
    subtitle: 'Who did what, when, and whether it was allowed. Records cannot be edited or removed.',
    helpKey: 'audit',
    actions: [button({ label: 'Download CSV', icon: 'action.export', variant: 'secondary', busyLabel: 'Preparing…', onClick: async () => {
      try { await api.download('/api/v1/audit', `remotehound-audit-${new Date().toISOString().slice(0, 10)}.csv`, { ...filters, format: 'csv' }); toast('Audit CSV downloaded', { tone: 'success' }) } catch (err) { toastError(err) }
    } })],
  })

  const apply = () => { ctx.setQuery(filters); g.reload(filters) }
  let timer = null
  const eventInput = h('input', { type: 'search', class: 'input input--sm', placeholder: 'e.g. session.open', 'aria-label': 'Event name', value: filters.event, spellcheck: 'false', maxlength: 100,
    onInput: () => { clearTimeout(timer); timer = setTimeout(() => { filters.event = eventInput.value.trim(); apply() }, 350) } })
  ctx.onCleanup(() => clearTimeout(timer))
  const toolbar = h('div', { class: 'filters' },
    h('div', { class: 'filter' }, h('span', { class: 'filter__label', 'aria-hidden': 'true' }, 'Event'), eventInput),
    filterSelect({ label: 'Outcome', value: filters.outcome, options: [{ value: 'success', label: 'Success' }, { value: 'failure', label: 'Failure' }, { value: 'denied', label: 'Denied' }], onChange: (v) => { filters.outcome = v; apply() } }))

  const g = grid({
    label: 'Audit events',
    helpScreen: 'audit',
    emptyKey: 'audit',
    exportName: 'audit',
    toolbar,
    query: filters,
    initialSort: { id: 'timestamp', dir: 'desc' },
    onClearFilters: () => { filters.event = ''; filters.outcome = ''; eventInput.value = ''; toolbar.querySelector('select').value = ''; apply() },
    load: ({ pageToken, query, signal }) => api.get('/api/v1/audit', { ...query, page_size: 100, page_token: pageToken }, { signal }),
    expand: (e) => h('div', { class: 'logdetail' },
      h('p', { class: 'muted' }, absoluteTime(e.timestamp), e.request_id ? [' · request ', h('a', { class: 'link mono', href: `/logs?request_id=${encodeURIComponent(e.request_id)}` }, e.request_id)] : null),
      h('pre', { class: 'logdetail__json', tabindex: '0', 'aria-label': 'Event attributes as JSON' }, JSON.stringify(e.attrs || {}, null, 2)),
      e.hash ? h('p', { class: 'muted mono wrap' }, `hash ${e.hash}`) : null),
    columns: [
      { id: 'timestamp', label: 'Time', render: (e) => relTime(e.timestamp) },
      { id: 'event', label: 'Event', render: (e) => h('span', { class: 'cell-stack' }, h('span', { class: 'cell-title' }, humanEvent(e.event)), h('span', { class: 'cell-sub mono' }, e.event)) },
      { id: 'outcome', label: 'Outcome', render: (e) => badge(e.outcome, OUTCOME_TONE[e.outcome] || 'neutral') },
      { id: 'user_email', label: 'User', render: (e) => h('span', { class: 'cell-stack' }, e.user_email || 'system', (e.user_roles || []).length ? h('span', { class: 'cell-sub' }, e.user_roles.join(', ')) : null) },
      { id: 'resource', label: 'Resource', className: 'mono' },
      { id: 'client_address', label: 'IP address', className: 'mono' },
    ],
  })
  append(p.body, g.el)
  return p.el
}
