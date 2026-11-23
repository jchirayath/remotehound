/**
 * Logs (/logs) — search server, client (device) and bundle (Guacamole/guacd/caddy) logs, and tail
 * them live.
 * Data: GET /api/v1/logs (filters source, level, q, request_id, device_id, limit) and
 * EventSource /api/v1/logs/stream with the same filters (each `data:` line is one LogRecord JSON).
 * Live tail keeps at most 1000 records in memory; pausing buffers new records until resumed.
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can } from '../lib/session.js'
import { page, grid, filterSelect, badge, button, toggle, iconButton, banner } from '../lib/ui.js'
import { absoluteTime, timeOfDay, deviceLabels } from '../lib/format.js'

const LEVEL_TONE = { DEBUG: 'neutral', INFO: 'info', WARN: 'warning', ERROR: 'danger' }
const MAX = 1000

export default function render(ctx) {
  const q0 = ctx.query || {}
  const filters = { source: q0.source || '', level: q0.level || '', q: q0.q || '', request_id: q0.request_id || '', device_id: q0.device_id || '' }
  const keys = new WeakMap()
  let seq = 0
  const keyOf = (r) => { if (!keys.has(r)) keys.set(r, ++seq); return keys.get(r) }

  let rows = []
  let pending = []
  let paused = false
  let closeStream = null
  let flushTimer = null

  const p = page({
    title: 'Logs',
    subtitle: 'Server, device and Guacamole logs in one place. Filter by request ID to follow one action end to end.',
    helpKey: 'logs',
  })

  const streamState = h('span', { class: 'stream-state', role: 'status' })
  const pauseBtn = button({ label: 'Pause', icon: 'domain.action.pause', variant: 'secondary', size: 'sm', onClick: () => setPaused(!paused) })
  pauseBtn.hidden = true
  const liveSwitch = toggle({ label: 'Live tail', onChange: (on) => (on ? startStream() : stopStream()) })

  function setPaused(v) {
    paused = v
    pauseBtn.querySelector('.btn__label').textContent = paused ? `Resume${pending.length ? ` (${pending.length} new)` : ''}` : 'Pause'
    replace(pauseBtn, icon(paused ? 'domain.action.run' : 'domain.action.pause'), pauseBtn.querySelector('.btn__label'))
    if (!paused) flush()
  }

  function flush() {
    flushTimer = null
    if (paused || !pending.length) return
    rows = pending.reverse().concat(rows).slice(0, MAX)
    pending = []
    g.setRows(rows)
  }

  function startStream() {
    stopStream()
    pauseBtn.hidden = false
    streamState.textContent = 'Connecting…'
    streamState.dataset.state = 'connecting'
    closeStream = api.stream('/api/v1/logs/stream', filters, {
      onMessage: (rec) => {
        pending.push(rec)
        if (pending.length > MAX) pending.shift()
        if (paused) { pauseBtn.querySelector('.btn__label').textContent = `Resume (${pending.length} new)`; return }
        if (!flushTimer) flushTimer = setTimeout(flush, 400)
      },
      onState: (s) => {
        streamState.dataset.state = s
        streamState.textContent = s === 'open' ? 'Live' : s === 'error' ? 'Reconnecting…' : ''
      },
    })
  }

  function stopStream() {
    closeStream?.()
    closeStream = null
    clearTimeout(flushTimer)
    flushTimer = null
    pauseBtn.hidden = true
    if (paused) setPaused(false)
    streamState.textContent = ''
  }
  ctx.onCleanup(stopStream)

  const apply = () => {
    ctx.setQuery(filters)
    g.reload(filters)
    if (closeStream) startStream()
  }

  let timer = null
  const text = (key, label, placeholder, max) => {
    const input = h('input', { type: 'search', class: 'input input--sm', placeholder, 'aria-label': label, value: filters[key], maxlength: max, spellcheck: 'false',
      onInput: () => { clearTimeout(timer); timer = setTimeout(() => { filters[key] = input.value.trim(); apply() }, 350) } })
    return h('div', { class: 'filter' }, h('span', { class: 'filter__label', 'aria-hidden': 'true' }, label), input)
  }
  ctx.onCleanup(() => clearTimeout(timer))

  const deviceFilter = filterSelect({ label: 'Device', value: filters.device_id, options: [], allLabel: 'All devices', onChange: (v) => { filters.device_id = v; apply() } })
  if (can('device.read')) {
    api.get('/api/v1/devices', { page_size: 200, order_by: 'name' }).then(r => {
      const sel = deviceFilter.querySelector('select')
      const labels = deviceLabels(r.data)
      for (const d of r.data || []) sel.append(h('option', { value: d.id }, labels.get(d.id)))
      sel.value = filters.device_id
    }).catch(() => deviceFilter.classList.add('is-unavailable'))
  }

  const requestFilter = text('request_id', 'Request ID', 'Paste a request ID', 64)
  const requestInput = requestFilter.querySelector('input')
  const toolbar = h('div', { class: 'filters' },
    text('q', 'Search', 'Text in message or event', 200),
    filterSelect({ label: 'Source', value: filters.source, options: [{ value: 'server', label: 'Server' }, { value: 'client', label: 'Devices' }, { value: 'bundle', label: 'Guacamole bundle' }], onChange: (v) => { filters.source = v; apply() } }),
    filterSelect({ label: 'Level', value: filters.level, options: ['DEBUG', 'INFO', 'WARN', 'ERROR'].map(l => ({ value: l, label: l })), onChange: (v) => { filters.level = v; apply() } }),
    can('device.read') ? deviceFilter : null,
    requestFilter)

  const g = grid({
    label: 'Log records',
    helpScreen: 'logs',
    emptyKey: 'logs',
    exportName: 'logs',
    searchable: false,
    toolbar,
    query: filters,
    rowKey: keyOf,
    initialSort: { id: 'timestamp', dir: 'desc' },
    onClearFilters: () => {
      for (const k of Object.keys(filters)) filters[k] = ''
      for (const i of toolbar.querySelectorAll('input, select')) i.value = ''
      apply()
    },
    load: async ({ query, signal }) => {
      const r = await api.get('/api/v1/logs', { ...query, limit: 500 }, { signal })
      rows = r.data || []
      return { data: rows, meta: {} }
    },
    expand: (r) => h('div', { class: 'logdetail' },
      h('p', { class: 'muted' }, absoluteTime(r.timestamp)),
      r.body ? h('pre', { class: 'logdetail__body' }, r.body) : null,
      h('pre', { class: 'logdetail__json', tabindex: '0', 'aria-label': 'Attributes as JSON' }, JSON.stringify(r.attributes || {}, null, 2)),
      r.attributes?.['app.request.id'] ? button({ label: 'Show this request only', icon: 'action.filter', variant: 'ghost', size: 'sm', onClick: () => {
        // Every record of the request, whatever its level, source or text: drop the other filters.
        for (const k of Object.keys(filters)) filters[k] = ''
        filters.request_id = r.attributes['app.request.id']
        for (const i of toolbar.querySelectorAll('input, select')) i.value = ''
        requestInput.value = filters.request_id
        apply()
      } }) : null),
    columns: [
      { id: 'timestamp', label: 'Time', className: 'mono nowrap', render: (r) => h('time', { datetime: r.timestamp, title: absoluteTime(r.timestamp) }, timeOfDay(r.timestamp)) },
      { id: 'severity_text', label: 'Level', render: (r) => badge(r.severity_text || 'INFO', LEVEL_TONE[r.severity_text] || 'neutral') },
      { id: 'source', label: 'Source' },
      { id: 'event', label: 'Event', className: 'mono', value: (r) => r['event.name'] },
      { id: 'body', label: 'Message', className: 'cell-wide' },
    ],
  })

  append(p.body, 
    h('div', { class: 'logbar' }, liveSwitch.el, streamState, pauseBtn,
      iconButton({ icon: 'domain.action.clear', label: 'Clear the records shown', onClick: () => { rows = []; pending = []; g.setRows([]) } })),
    filters.level === 'DEBUG' ? banner('info', 'Debug records are only kept when the log level is DEBUG', 'Change the level on the Debug screen if you see none.') : null,
    g.el)
  return p.el
}
