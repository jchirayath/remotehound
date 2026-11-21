/**
 * Devices (/devices) — every device the user can see, with presence, services and filters.
 * Data: GET /api/v1/devices (cursor paged; filters q, online, status, group_id, os are server-side and
 * mirrored into the URL so a filtered view can be shared). Row click opens /devices/:id.
 */
import { h, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can, groups, groupMap } from '../lib/session.js'
import { page, grid, filterSelect, linkButton, presence, groupPill, serviceChip, osIcon, relTime, badge, installScope } from '../lib/ui.js'
import { osLabel, toDate } from '../lib/format.js'

export default function render(ctx) {
  const q0 = ctx.query || {}
  const query = { q: q0.q || '', online: q0.online || '', status: q0.status || '', group_id: q0.group_id || '', os: q0.os || '' }
  let gmap = new Map()

  const p = page({
    title: 'Devices',
    subtitle: 'Machines enrolled with RemoteHound. Open one to connect, edit or diagnose it.',
    helpKey: 'devices',
    actions: [can('enrollment.create') ? linkButton({ href: '/enroll', label: 'Enroll a device', icon: 'domain.nav.enroll', variant: 'primary' }) : null],
  })

  const apply = () => { ctx.setQuery(query); g.reload(query) }
  const clear = () => {
    for (const k of Object.keys(query)) query[k] = ''
    qInput.value = ''
    for (const s of toolbar.querySelectorAll('select')) s.value = ''
    apply()
  }

  let timer = null
  const qInput = h('input', { type: 'search', class: 'input input--search', placeholder: 'Search name or hostname', 'aria-label': 'Search devices', value: query.q, maxlength: 100,
    onInput: () => { clearTimeout(timer); timer = setTimeout(() => { query.q = qInput.value.trim(); apply() }, 300) } })
  const groupFilter = filterSelect({ label: 'Group', value: query.group_id, options: [], onChange: (v) => { query.group_id = v; apply() } })
  const toolbar = h('div', { class: 'filters' },
    h('div', { class: 'grid__search' }, icon('action.search', { size: 'sm' }), qInput),
    filterSelect({ label: 'Presence', value: query.online, options: [{ value: 'true', label: 'Online' }, { value: 'false', label: 'Offline' }], onChange: (v) => { query.online = v; apply() } }),
    filterSelect({ label: 'Status', value: query.status, options: [{ value: 'active', label: 'Active' }, { value: 'pending', label: 'Pending' }, { value: 'disabled', label: 'Disabled' }], onChange: (v) => { query.status = v; apply() } }),
    can('group.read') ? groupFilter : null,
    filterSelect({ label: 'OS', value: query.os, options: ['linux', 'macos', 'windows', 'unknown'].map(o => ({ value: o, label: osLabel(o) })), onChange: (v) => { query.os = v; apply() } }))

  // Bind the group filter to real groups (UX-4).
  groups().then(list => {
    const sel = groupFilter.querySelector('select')
    for (const gr of list) sel.append(h('option', { value: gr.id }, gr.name))
    sel.value = query.group_id
  }).catch(() => groupFilter.classList.add('is-unavailable'))

  const g = grid({
    label: 'Devices',
    helpScreen: 'devices',
    emptyKey: 'devices',
    exportName: 'devices',
    searchable: false,
    toolbar,
    query,
    onClearFilters: clear,
    initialSort: { id: 'name', dir: 'asc' },
    rowHref: (d) => `/devices/${encodeURIComponent(d.id)}`,
    load: async ({ pageToken, query: qq, signal }) => {
      gmap = await groupMap()
      return api.get('/api/v1/devices', { ...qq, page_size: 50, page_token: pageToken }, { signal })
    },
    columns: [
      { id: 'name', label: 'Name', primary: true, render: (d) => h('span', { class: 'cell-stack' },
        h('span', { class: 'cell-title' }, d.name, (d.identity_warnings || []).length ? h('span', { title: d.identity_warnings.map(w => w.message).join(' ') }, ' ', badge('Check identity', 'warning', 'status.warning')) : null),
        d.hostname && d.hostname !== d.name ? h('span', { class: 'cell-sub mono' }, d.hostname) : null) },
      { id: 'online', label: 'Presence', value: (d) => (d.status === 'disabled' ? 'disabled' : d.status === 'pending' ? 'pending' : d.online ? 'online' : 'offline'), render: (d) => presence(d) },
      { id: 'os', label: 'OS', value: (d) => osLabel(d.os), render: (d) => osIcon(d.os, { withText: true }) },
      { id: 'group', label: 'Group', value: (d) => gmap.get(d.group_id)?.name || '', render: (d) => groupPill(gmap.get(d.group_id)) },
      { id: 'services', label: 'Services', sortable: false, value: (d) => (d.services || []).map(s => s.kind).join(' '), render: (d) => (d.services || []).length ? h('span', { class: 'chips' }, d.services.map(serviceChip)) : null },
      { id: 'last_seen_at', label: 'Last seen', value: (d) => (d.online ? Date.now() : toDate(d.last_seen_at)?.getTime() || 0), render: (d) => (d.online ? h('span', { class: 'live-text' }, 'Now') : relTime(d.last_seen_at)) },
      { id: 'install_scope', label: 'Install', value: (d) => d.install_scope || '', render: (d) => installScope(d) },
      { id: 'client_version', label: 'Client', className: 'mono' },
    ],
  })
  ctx.onCleanup(() => clearTimeout(timer))
  // Presence changes quickly; refresh quietly every 20 s.
  const t = setInterval(() => { if (!document.hidden) g.refresh() }, 20000)
  ctx.onCleanup(() => clearInterval(t))

  append(p.body, g.el)
  return p.el
}
