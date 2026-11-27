/**
 * Debug (/debug) — runtime facts, live tunnels, background jobs (Run now), runtime log level and the
 * redacted diagnostics bundle.
 * Data: GET /api/v1/debug/runtime, GET /api/v1/debug/tunnels (refreshed every 10 s), GET /api/v1/jobs,
 * POST /api/v1/jobs/{name}/run, PUT /api/v1/debug/log-level, GET /api/v1/debug/bundle (download).
 */
import { h, replace, append } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { can } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import { page, kv, grid, button, badge, relTime, segmented, load, toast, toastError, banner, skeleton } from '../lib/ui.js'
import { duration, bytes, number, durationMs, serviceLabel } from '../lib/format.js'

export default function render(ctx) {
  const p = page({
    title: 'Debug',
    subtitle: 'What the server is doing right now. Use this with the Logs screen when something misbehaves.',
    helpKey: 'debug',
    actions: [button({ label: 'Download diagnostics', icon: 'domain.action.bundle', variant: 'secondary', permission: 'debug.read', busyLabel: 'Preparing…',
      onClick: async () => {
        try { const name = await api.download('/api/v1/debug/bundle', `remotehound-diagnostics-${new Date().toISOString().slice(0, 10)}.json`); toast(`Saved ${name}`, { tone: 'success', detail: 'Secrets are redacted; review it before sharing.' }) } catch (err) { toastError(err) }
      } })],
  })

  const runtimeBox = h('div')
  const levelBox = h('div', { class: 'level' }, skeleton('text', 2))

  function runtime(rt) {
    const levelCtl = segmented({
      label: 'Server log level', value: (rt.log_level || 'INFO').toUpperCase(), disabled: !can('debug.write'),
      options: ['DEBUG', 'INFO', 'WARN', 'ERROR'].map(l => ({ value: l, label: l })),
      onChange: async (lvl) => {
        try { await api.put('/api/v1/debug/log-level', { level: lvl }); toast(`Log level set to ${lvl}`, { tone: 'success', detail: lvl === 'DEBUG' ? 'DEBUG is verbose; set it back to INFO when you are done.' : '' }) } catch (err) { toastError(err) }
      },
    })
    replace(levelBox, h('h2', { class: 'card__title' }, 'Log level'), h('p', { class: 'muted' }, fieldHelp('debug.log_level')), levelCtl,
      !can('debug.write') ? h('p', { class: 'muted' }, 'Your role can view but not change the level.') : null)
    return h('div', null,
      rt.store_recovered_from_backup ? banner('warning', 'State was restored from a backup at start-up', fieldHelp('debug.store_recovered_from_backup')) : null,
      kv([
        ['Version', h('span', { class: 'mono' }, `${rt.version || '?'}${rt.commit ? ` (${String(rt.commit).slice(0, 10)})` : ''}`)],
        ['Go', h('span', { class: 'mono' }, rt.go_version)],
        ['Started', relTime(rt.started_at)],
        ['Uptime', duration(rt.uptime_seconds)],
        ['Goroutines', number(rt.goroutines), fieldHelp('debug.goroutines')],
        ['Heap', bytes(rt.heap_bytes)],
        ['Tunnels online', number(rt.tunnels_online)],
        ['SSH listener', h('span', { class: 'mono' }, rt.ssh_listen)],
        ['Auth mode', rt.auth_mode],
        ['Store', h('span', { class: 'mono wrap' }, rt.store_path)],
      ]))
  }

  const tunnels = grid({
    label: 'Live tunnels',
    helpScreen: 'debug',
    emptyKey: 'debug.tunnels',
    exportName: 'tunnels',
    rowKey: (t) => t.device_id,
    initialSort: { id: 'device_name', dir: 'asc' },
    load: ({ signal }) => api.get('/api/v1/debug/tunnels', null, { signal }),
    expand: (t) => grid({
      label: `Forwards for ${t.device_name}`, helpScreen: 'debug', emptyKey: 'debug.tunnels', searchable: false, rows: t.forwards || [], rowKey: (f) => f.kind,
      columns: [
        { id: 'kind', label: 'Service', value: (f) => serviceLabel(f.kind) },
        { id: 'remote_port', label: 'Device port', className: 'mono' },
        { id: 'internal_port', label: 'Tunnel port', className: 'mono' },
        { id: 'active_conns', label: 'Connections', align: 'end' },
        { id: 'bytes_in', label: 'In', align: 'end', render: (f) => bytes(f.bytes_in) },
        { id: 'bytes_out', label: 'Out', align: 'end', render: (f) => bytes(f.bytes_out) },
      ],
    }).el,
    columns: [
      { id: 'device_name', label: 'Device', primary: true, render: (t) => h('a', { href: `/devices/${encodeURIComponent(t.device_id)}`, class: 'link' }, t.device_name || t.device_id) },
      { id: 'remote_address', label: 'From', className: 'mono' },
      { id: 'connected_since', label: 'Connected', render: (t) => relTime(t.connected_since) },
      { id: 'last_keepalive_at', label: 'Last keepalive', render: (t) => relTime(t.last_keepalive_at) },
      { id: 'forwards', label: 'Forwards', value: (t) => (t.forwards || []).map(f => `${f.kind}:${f.remote_port}→${f.internal_port}`).join(' '), render: (t) => h('span', { class: 'chips' }, (t.forwards || []).map(f => h('span', { class: 'chip' }, `${serviceLabel(f.kind)} ${f.active_conns ? `· ${f.active_conns}` : ''}`))) },
      { id: 'client_version', label: 'Client', className: 'mono' },
    ],
  })

  const jobs = grid({
    label: 'Background jobs',
    helpScreen: 'debug',
    emptyKey: 'debug.jobs',
    exportName: 'jobs',
    rowKey: (j) => j.name,
    initialSort: { id: 'name', dir: 'asc' },
    load: ({ signal }) => api.get('/api/v1/jobs', null, { signal }),
    columns: [
      { id: 'name', label: 'Job', primary: true, render: (j) => h('span', { class: 'cell-stack' }, h('span', { class: 'cell-title mono' }, j.name), j.description ? h('span', { class: 'cell-sub' }, j.description) : null) },
      { id: 'schedule', label: 'Schedule', className: 'mono' },
      { id: 'status', label: 'Status', value: (j) => (j.running ? 'running' : j.consecutive_failures ? 'failing' : 'ok'),
        render: (j) => (j.running ? badge('Running', 'info') : j.consecutive_failures ? h('span', { class: 'cell-stack' }, badge(`Failing ×${j.consecutive_failures}`, 'danger'), j.last_error ? h('span', { class: 'cell-sub mono' }, j.last_error) : null) : badge('OK', 'success')) },
      { id: 'last_run_at', label: 'Last run', render: (j) => h('span', { class: 'cell-stack' }, relTime(j.last_run_at), j.last_duration_ms != null ? h('span', { class: 'cell-sub' }, durationMs(j.last_duration_ms)) : null) },
      { id: 'last_success_at', label: 'Last success', render: (j) => relTime(j.last_success_at) },
      { id: 'next_run_at', label: 'Next run', render: (j) => relTime(j.next_run_at, { never: 'On demand' }) },
      can('job.run') ? { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (j) => button({
        label: 'Run now', icon: 'domain.action.run', variant: 'secondary', size: 'sm', disabled: j.running,
        onClick: async () => {
          try { await api.post(`/api/v1/jobs/${encodeURIComponent(j.name)}/run`); toast(`${j.name} started`, { tone: 'success' }); setTimeout(() => jobs.refresh(), 1500) } catch (err) { toastError(err) }
        },
      }) } : null,
    ].filter(Boolean),
  })

  const t = setInterval(() => { if (!document.hidden) { tunnels.refresh(); jobs.refresh() } }, 10000)
  ctx.onCleanup(() => clearInterval(t))

  append(p.body, 
    h('div', { class: 'split' },
      h('section', { class: 'card', 'aria-labelledby': 'rt-h' }, h('h2', { id: 'rt-h', class: 'card__title' }, 'Runtime'), runtimeBox),
      h('section', { class: 'card', 'aria-label': 'Log level' }, levelBox)),
    h('section', { class: 'section', 'aria-labelledby': 'tun-h' }, h('h2', { id: 'tun-h', class: 'section__title' }, 'Live tunnels'), tunnels.el),
    h('section', { class: 'section', 'aria-labelledby': 'job-h' }, h('h2', { id: 'job-h', class: 'section__title' }, 'Background jobs'), jobs.el))
  load(runtimeBox, { load: () => api.get('/api/v1/debug/runtime', null, { signal: ctx.signal }).then(r => r.data), render: runtime })
  return p.el
}
