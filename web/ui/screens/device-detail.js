/**
 * Device detail (/devices/:id) — connect, edit, manage services, see sessions and client logs,
 * diagnose, and disable/delete.
 *
 * Data: GET /api/v1/devices/{id}; PATCH with If-Match (412 → conflict banner + reload);
 * PUT/DELETE /devices/{id}/services/{kind}; POST connect | probe | reconnect | disable | enable;
 * DELETE /devices/{id}; GET /devices/{id}/logs; GET /sessions?device_id=.
 * Tabs are mirrored in ?tab= so a link can open a specific tab.
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can, groups, groupMap } from '../lib/session.js'
import {
  page, tabs, button, iconButton, kv, badge, presence, groupPill, osIcon, relTime, field, applyFieldErrors, formError,
  banner, drawer, confirmDialog, toast, toastError, grid, errorState, skeleton, emptyState, toggle, describeError, copyButton, unmount, linkButton, installScope,
} from '../lib/ui.js'
import { osLabel, serviceLabel, DEFAULT_PORTS, absoluteTime, durationMs, bytes, duration, between } from '../lib/format.js'
import { fieldHelp } from '../lib/help.js'
import { openSession } from '../lib/connect.js'
import { openCredentialForm } from './credential-form.js'

const KINDS = ['ssh', 'rdp', 'vnc']
/** Options the server allow-lists (ServiceUpsert.options), and which protocols they apply to. */
export const SERVICE_OPTIONS = {
  security: { kinds: ['rdp'], type: 'select', label: 'RDP security mode', choices: ['any', 'nla', 'nla-ext', 'tls', 'rdp', 'vmconnect'] },
  'ignore-cert': { kinds: ['rdp'], type: 'checkbox', label: 'Ignore the RDP server certificate' },
  'color-depth': { kinds: ['rdp', 'vnc'], type: 'select', label: 'Colour depth', choices: ['8', '16', '24', '32'] },
  'enable-sftp': { kinds: ['ssh', 'rdp', 'vnc'], type: 'checkbox', label: 'Enable file transfer (SFTP)' },
  'read-only': { kinds: ['ssh', 'rdp', 'vnc'], type: 'checkbox', label: 'View only (no keyboard or mouse input)' },
}

export default function render(ctx) {
  const id = ctx.params.id
  const path = `/api/v1/devices/${encodeURIComponent(id)}`
  const root = h('div', { class: 'page' }, skeleton('detail', 3))
  let device = null
  let gmap = new Map()
  let activeTab = ctx.query?.tab || 'overview'

  async function loadDevice() {
    replace(root, skeleton('detail', 3))
    try {
      const [r, gm] = await Promise.all([api.get(path, null, { signal: ctx.signal }), groupMap(), loadMyCreds()])
      device = r.data
      gmap = gm
      ctx.setTitle(device.name)
      paint()
    } catch (err) {
      if (err?.name === 'AbortError') return
      const p = page({ title: 'Device', helpKey: 'device', back: { href: '/devices', label: 'Devices' } })
      append(p.body, err.status === 404 ? notRegistered() : errorState(err, loadDevice))
      replace(root, ...p.el.childNodes)
    }
  }

  /** 404: the ID is not (or no longer) a device — say what that means and how to register the machine. */
  function notRegistered() {
    const host = location.origin
    const st = emptyState('device.not_registered')
    st.querySelector('.state__body')?.after(
      h('div', { class: 'state__hint' },
        h('p', { class: 'muted' }, 'The command has a one-time code in it, so it is only shown when you create one. It looks like this:'),
        h('p', null, h('span', { class: 'muted' }, 'macOS / Linux: '), h('code', null, `curl -fsSL ${host}/e/CODE | sh`)),
        h('p', null, h('span', { class: 'muted' }, 'Windows PowerShell: '), h('code', null, `irm ${host}/e/CODE | iex`))))
    const all = linkButton({ href: '/devices', label: 'All devices', icon: 'domain.nav.devices', variant: 'ghost' })
    const actions = st.querySelector('.state__actions')
    if (actions) actions.append(all)
    else st.append(h('div', { class: 'state__actions' }, all))
    return st
  }

  /** A sign this device is not the machine its name says (wrong machine enrolled, or enrolled twice). */
  function identityBanner(w) {
    const actions = []
    const host = (device.hostname || '').replace(/\.local$/i, '')
    if (w.code === 'NAME_OS_MISMATCH' && host && can('device.update')) {
      actions.push(button({ label: `Rename to ${host}`, icon: 'action.edit', variant: 'secondary', size: 'sm', onClick: async () => {
        try {
          const r = await api.patch(path, { name: host }, device.etag)
          device = r.data
          toast(`Renamed to ${host}`, { tone: 'success' })
          paint()
        } catch (err) {
          if (err.status === 412 || err.code === 'PRECONDITION_FAILED') { toast('Someone else changed this device; reloading', { tone: 'warning' }); loadDevice() } else toastError(err)
        }
      } }))
    }
    if (w.code === 'DUPLICATE_HOST' && w.other_device_id) {
      actions.push(linkButton({ href: `/devices/${encodeURIComponent(w.other_device_id)}`, label: `Open ${w.other_device_name || 'the other entry'}`, icon: 'domain.nav.devices', size: 'sm' }))
    }
    const title = w.code === 'DUPLICATE_HOST' ? 'This machine may be enrolled twice' : 'This may not be the machine its name says'
    return banner('warning', title, w.message, actions.length ? h('div', { class: 'btn-row' }, actions) : null)
  }

  /* ── header + connect ── */

  /** The signed-in user's saved logins for this device: service kind → credential. */
  let myCreds = new Map()
  async function loadMyCreds() {
    if (!can('device.connect')) return
    try {
      const r = await api.get('/api/v1/me/credentials')
      myCreds = new Map((r.data || []).filter(c => c.device_id === id).map(c => [c.service, c]))
    } catch (err) {
      myCreds = new Map() // optional decoration: Connect still works with the device login
    }
  }

  function connect(kind, btn) {
    return openSession(() => api.post(`${path}/connect`, { service: kind }), {
      what: `${serviceLabel(kind)} to ${device.name}`, button: btn,
      // RDP with NLA and Mac Screen Sharing need a login up front: ask for it here, then offer Connect.
      onError: (err) => {
        if (err?.code !== 'CREDENTIALS_REQUIRED' || !can('device.connect')) return false
        openCredentialForm({
          deviceId: id, service: kind,
          intro: { title: `${serviceLabel(kind)} needs a login first`, body: err.detail || 'Save the username and password for this machine, then connect.' },
          onSaved: async () => {
            await loadMyCreds(); paint()
            toast('Login saved', { tone: 'success', detail: `Connect to open ${serviceLabel(kind)} with it.`, action: { label: 'Connect', onClick: () => connect(kind) } })
          },
        })
        return true
      },
    })
  }
  /** Services that cannot start without a login (the server refuses them; see missingLogin in Go). */
  const needsLogin = (s) => !myCreds.get(s.kind) && !s.has_credential &&
    ((s.kind === 'vnc' && device.os === 'macos') || (s.kind === 'rdp' && ['', 'any', 'nla', 'nla-ext'].includes(s.options?.security || '')))

  function connectBar() {
    const svcs = device.services || []
    if (!svcs.length) return h('div', { class: 'connect connect--empty' }, h('p', { class: 'muted' }, 'No services configured. Add one in the Services tab to connect.'))
    const allowed = can('device.connect')
    return h('div', { class: 'connect', role: 'group', 'aria-label': 'Connect' }, svcs.map(s => {
      const reason = !allowed ? 'Your role cannot open sessions' : device.status === 'disabled' ? 'The device is disabled'
        : !device.online ? 'The device is offline' : !s.forwarded ? `${serviceLabel(s.kind)} is not being forwarded by the device` : ''
      const mine = myCreds.get(s.kind)
      const b = h('button', { type: 'button', class: ['connect__btn', !reason && 'is-ready'], disabled: !!reason, title: reason || `Open ${serviceLabel(s.kind)} in a new tab` },
        h('span', { class: 'connect__icon' }, icon(`domain.service.${s.kind}`, { size: 'lg' })),
        h('span', { class: 'connect__text' },
          h('span', { class: 'connect__label' }, `Connect ${serviceLabel(s.kind)}`),
          h('span', { class: 'connect__sub' }, reason || (mine ? `your login${mine.username ? ` · ${mine.username}` : ''}` : needsLogin(s) ? (device.os === 'macos' && s.kind === 'vnc' ? 'asks for your macOS login first' : 'asks for a login first') : `port ${s.remote_port}${s.username ? ` · ${s.username}` : ''}`))))
      b.addEventListener('click', () => connect(s.kind, b))
      const own = allowed ? h('button', { type: 'button', class: 'connect__own', onClick: () => openCredentialForm({
        deviceId: id, service: s.kind, existing: mine ? { ...mine, device_name: device.name } : undefined,
        onSaved: async () => { await loadMyCreds(); paint() },
      }) }, icon('domain.object.credential', { size: 'sm' }), mine ? `Using my own login · change` : 'Use my own login') : null
      return h('div', { class: 'connect__item' }, b, own)
    }))
  }

  function paint() {
    unmount(root)
    const group = gmap.get(device.group_id)
    const p = page({
      title: device.name,
      helpKey: 'device',
      back: { href: '/devices', label: 'Devices' },
      lead: h('span', { class: `device-tile device-tile--${device.online ? 'online' : 'offline'}`, 'aria-hidden': 'true' }, icon(`domain.os.${['linux', 'macos', 'windows'].includes(device.os) ? device.os : 'unknown'}`, { size: 'lg' })),
      subtitle: h('span', { class: 'device-sub' }, presence(device), device.hostname ? h('span', { class: 'mono' }, device.hostname) : null,
        h('span', null, osLabel(device.os), device.os_version ? ` ${device.os_version}` : ''), groupPill(group),
        device.online && device.connected_since ? h('span', { class: 'muted' }, 'connected ', relTime(device.connected_since)) : (!device.online ? h('span', { class: 'muted' }, 'last seen ', relTime(device.last_seen_at)) : null)),
      actions: [iconButton({ icon: 'action.refresh', label: 'Refresh device', onClick: loadDevice })],
    })
    if (device.status === 'disabled') append(p.body, banner('warning', 'This device is disabled', 'Its tunnel is closed and new logins are refused. Enable it in the danger zone below the Overview tab.'))
    else if (device.status === 'pending') append(p.body, banner('info', 'Waiting for the first connection', 'The device has redeemed its code but has not opened its tunnel yet. Check its client logs if this takes more than a minute.'))
    else if (!device.online) append(p.body, banner('info', 'This device is not connected',
      'If the machine is on, RemoteHound may have been removed from it or reinstalled. Register it again: create a code and run the command it shows on the machine. That adds a new entry, so delete this one afterwards.',
      can('enrollment.create') ? linkButton({ href: `/enroll?name=${encodeURIComponent(device.name)}`, label: 'Get the install command', icon: 'domain.nav.enroll', size: 'sm' }) : null))
    for (const w of device.identity_warnings || []) append(p.body, identityBanner(w))
    append(p.body, connectBar())
    const t = tabs({
      label: 'Device sections',
      active: activeTab,
      onChange: (tid) => { activeTab = tid; ctx.setQuery(tid === 'overview' ? {} : { tab: tid }) },
      tabs: [
        { id: 'overview', label: 'Overview', icon: 'status.info', render: overviewTab },
        { id: 'services', label: 'Services', icon: 'domain.object.tunnel', render: servicesTab },
        can('session.read') ? { id: 'sessions', label: 'Sessions', icon: 'domain.nav.sessions', render: sessionsTab } : null,
        { id: 'logs', label: 'Client logs', icon: 'domain.nav.logs', render: logsTab },
        { id: 'diagnostics', label: 'Diagnostics', icon: 'domain.action.probe', render: diagnosticsTab },
      ].filter(Boolean),
    })
    append(p.body, t.el)
    replace(root, ...p.el.childNodes)
    root.querySelector('.page__title')?.focus({ preventScroll: true })
  }

  /* ── overview tab ── */

  function overviewTab(panel) {
    const facts = h('section', { class: 'card', 'aria-labelledby': 'facts-h' },
      h('h2', { id: 'facts-h', class: 'card__title' }, 'Facts'),
      kv([
        ['Device ID', h('span', { class: 'mono copyable' }, device.id, copyButton(device.id, { compact: true, variant: 'ghost', label: 'Copy device ID' }))],
        ['Status', badge(device.status, device.status === 'active' ? 'success' : device.status === 'pending' ? 'warning' : 'neutral')],
        ['Hostname', device.hostname ? h('span', { class: 'mono' }, device.hostname) : null],
        ['Operating system', h('span', null, osIcon(device.os, { withText: true }), device.os_version ? ` ${device.os_version}` : '')],
        ['Transport', device.transport, fieldHelp('device.transport')],
        ['Key fingerprint', device.key_fingerprint ? h('span', { class: 'mono wrap' }, device.key_fingerprint) : null, fieldHelp('device.key_fingerprint')],
        ['Last IP', device.last_ip ? h('span', { class: 'mono' }, device.last_ip) : null],
        ['Last seen', device.online ? h('span', { class: 'live-text' }, 'Now') : relTime(device.last_seen_at)],
        ['Connected since', device.connected_since ? relTime(device.connected_since) : null],
        ['Install type', h('span', { class: 'cell-stack' }, installScope(device, { long: true }),
          device.install_scope === 'user' && can('enrollment.create')
            ? h('a', { href: `/enroll?name=${encodeURIComponent(device.name)}` }, 'Make it permanent') : null), fieldHelp('device.install_scope')],
        ['Client version', device.client_version ? h('span', { class: 'mono' }, device.client_version) : null],
        ['Enrolled', absoluteTime(device.created_at)],
        ['Updated', relTime(device.updated_at)],
      ]))
    append(panel, h('div', { class: 'split' }, facts, editCard()), dangerZone())
  }

  function editCard() {
    const editable = can('device.update')
    const f = {
      name: field({ id: 'device.name', label: 'Name', value: device.name, required: true, maxlength: 64, disabled: !editable }),
      group_id: field({ id: 'device.group_id', label: 'Group', type: 'select', options: [{ value: '', label: 'No group' }], value: device.group_id || '', disabled: !editable }),
      tags: field({ id: 'device.tags', label: 'Tags', value: (device.tags || []).join(', '), placeholder: 'kiosk, floor-2', disabled: !editable }),
      notes: field({ id: 'device.notes', label: 'Notes', type: 'textarea', value: device.notes || '', maxlength: 2000, rows: 4, disabled: !editable }),
    }
    groups().then(list => {
      for (const g of list) f.group_id.input.append(h('option', { value: g.id }, g.name))
      f.group_id.set(device.group_id || '')
    }).catch(() => f.group_id.setError('Groups could not be loaded; the current group is kept.'))
    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form card', 'aria-labelledby': 'edit-h', novalidate: true },
      h('h2', { id: 'edit-h', class: 'card__title' }, 'Details'),
      msg, f.name.el, f.group_id.el, f.tags.el, f.notes.el,
      editable ? h('div', { class: 'form__actions' }, button({ label: 'Save changes', icon: 'action.save', variant: 'primary', type: 'submit' })) : h('p', { class: 'muted' }, 'Your role can view this device but not edit it.'))
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      const name = f.name.get().trim()
      if (!name) { f.name.setError('Enter a name (up to 64 characters).'); f.name.input.focus(); return }
      const tags = f.tags.get().split(',').map(s => s.trim()).filter(Boolean)
      if (tags.length > 20 || tags.some(t => t.length > 32)) { f.tags.setError('Up to 20 tags, each up to 32 characters.'); return }
      const patch = {}
      if (name !== device.name) patch.name = name
      if ((f.group_id.get() || '') !== (device.group_id || '')) patch.group_id = f.group_id.get()
      if (f.notes.get() !== (device.notes || '')) patch.notes = f.notes.get()
      if (tags.join(',') !== (device.tags || []).join(',')) patch.tags = tags
      if (!Object.keys(patch).length) { toast('Nothing to save', { tone: 'info', timeout: 2000 }); return }
      const submit = form.querySelector('button[type=submit]')
      submit.disabled = true
      try {
        const r = await api.patch(path, patch, device.etag)
        device = r.data
        toast('Device saved', { tone: 'success' })
        paint()
      } catch (err) {
        if (err.status === 412 || err.code === 'PRECONDITION_FAILED') {
          replace(msg, banner('warning', 'Someone else changed this device', 'Your edits were not saved. Reload to see the latest version, then make your change again.',
            button({ label: 'Reload', icon: 'action.refresh', variant: 'secondary', onClick: loadDevice })))
        } else if (!applyFieldErrors(f, err)) replace(msg, formError(err))
      } finally { submit.disabled = false }
    })
    return form
  }

  function dangerZone() {
    const items = []
    if (can('device.update')) {
      const disabled = device.status === 'disabled'
      items.push(h('div', { class: 'danger__item' },
        h('div', null, h('h3', { class: 'danger__title' }, disabled ? 'Enable this device' : 'Disable this device'),
          h('p', { class: 'muted' }, fieldHelp(disabled ? 'device.enable' : 'device.disable'))),
        button({
          label: disabled ? 'Enable' : 'Disable', icon: 'domain.action.disable', variant: disabled ? 'secondary' : 'danger',
          onClick: async () => {
            if (!disabled && !(await confirmDialog({ title: `Disable ${device.name}?`, body: 'The tunnel closes now, active sessions end, and the device cannot reconnect until you enable it again.', confirmLabel: 'Disable', tone: 'danger' }))) return
            try {
              const r = await api.post(`${path}/${disabled ? 'enable' : 'disable'}`)
              device = r.data || { ...device, status: disabled ? 'active' : 'disabled' }
              toast(disabled ? 'Device enabled' : 'Device disabled', { tone: 'success' })
              paint()
            } catch (err) { toastError(err) }
          },
        })))
    }
    if (can('device.delete')) {
      items.push(h('div', { class: 'danger__item' },
        h('div', null, h('h3', { class: 'danger__title' }, 'Delete this device'), h('p', { class: 'muted' }, fieldHelp('device.delete'))),
        button({
          label: 'Delete', icon: 'action.delete', variant: 'danger',
          onClick: async () => {
            const ok = await confirmDialog({ title: `Delete ${device.name}?`, body: 'Its key is revoked, its tunnel closes and its history stays in the audit log. The person at the device must enrol again to come back.', confirmLabel: 'Delete device', tone: 'danger', typed: device.name })
            if (!ok) return
            try {
              await api.del(path)
              toast(`${device.name} deleted`, { tone: 'success' })
              ctx.navigate('/devices')
            } catch (err) { toastError(err) }
          },
        })))
    }
    return items.length ? h('section', { class: 'danger', 'aria-labelledby': 'dz-h' }, h('h2', { id: 'dz-h', class: 'card__title' }, 'Danger zone'), items) : null
  }

  /* ── services tab ── */

  function servicesTab(panel) {
    const svcs = device.services || []
    const missing = KINDS.filter(k => !svcs.some(s => s.kind === k))
    const editable = can('device.update')
    append(panel, 
      h('div', { class: 'section-head' },
        h('p', { class: 'muted' }, 'Services are the remote-access ports on the device that the tunnel forwards. Credentials are sealed on the server and never shown again.'),
        editable && missing.length ? h('div', { class: 'btn-row' }, missing.map(k => button({ label: `Add ${serviceLabel(k)}`, icon: 'action.add', variant: 'secondary', onClick: () => serviceForm(k, null) }))) : null),
      svcs.length ? h('ul', { class: 'svc-list', role: 'list' }, svcs.map(s => h('li', { class: 'svc card' },
        h('div', { class: 'svc__head' },
          h('span', { class: `svc__icon ${s.forwarded ? 'is-live' : ''}`, 'aria-hidden': 'true' }, icon(`domain.service.${s.kind}`, { size: 'lg' })),
          h('div', null, h('h3', { class: 'svc__title' }, serviceLabel(s.kind)),
            s.forwarded ? badge('Forwarded', 'success', 'domain.presence.online') : badge('Not forwarded', 'neutral', 'domain.presence.offline')),
          editable ? h('div', { class: 'svc__actions' },
            iconButton({ icon: 'action.edit', label: `Edit ${serviceLabel(s.kind)}`, onClick: () => serviceForm(s.kind, s) }),
            iconButton({ icon: 'action.delete', label: `Remove ${serviceLabel(s.kind)}`, onClick: () => removeService(s) })) : null),
        kv([
          ['Port on device', h('span', { class: 'mono' }, String(s.remote_port)), fieldHelp('device.remote_port')],
          ['Tunnel port', s.internal_port ? h('span', { class: 'mono' }, String(s.internal_port)) : 'Assigned on first connect', fieldHelp('device.internal_port')],
          ['Username', s.username ? h('span', { class: 'mono' }, s.username) : null],
          ['Password', s.has_credential ? badge('Stored', 'info', 'object.lock') : h('span', { class: 'muted' }, 'Asked at connect')],
          ['Options', Object.keys(s.options || {}).length ? h('span', { class: 'chips' }, Object.entries(s.options).map(([k, v]) => h('span', { class: 'chip' }, `${k}: ${v}`))) : null],
        ]))))
        : emptyState('device.services', { action: editable ? button({ label: 'Add SSH', icon: 'action.add', variant: 'primary', onClick: () => serviceForm('ssh', null) }) : null }))
  }

  function serviceForm(kind, svc) {
    const isNew = !svc
    const kindField = field({ id: 'device.service_kind', label: 'Protocol', type: 'select', value: kind, options: KINDS.filter(k => !isNew ? k === kind : !(device.services || []).some(s => s.kind === k)).map(k => ({ value: k, label: serviceLabel(k) })), disabled: !isNew })
    const f = {
      remote_port: field({ id: 'device.remote_port', label: 'Port on the device', type: 'number', min: 1, max: 65535, value: svc?.remote_port ?? DEFAULT_PORTS[kind], required: true, mono: true }),
      username: field({ id: 'device.username', label: 'Username', value: svc?.username || '', maxlength: 128, autocomplete: 'off' }),
      password: field({ id: 'device.password', label: 'Password', type: 'password', maxlength: 512, placeholder: svc?.has_credential ? 'Stored — leave empty to keep' : 'Optional' }),
    }
    const clearPw = svc?.has_credential ? field({ id: 'device.clear_password', label: 'Remove the stored password', type: 'checkbox', value: false }) : null
    const optWrap = h('fieldset', { class: 'fieldset' }, h('legend', { class: 'field__label' }, 'Options'))
    const optFields = {}
    const paintOptions = () => {
      const k = kindField.get()
      replace(optWrap, h('legend', { class: 'field__label' }, 'Options'))
      for (const [name, spec] of Object.entries(SERVICE_OPTIONS)) {
        if (!spec.kinds.includes(k)) { delete optFields[name]; continue }
        const cur = svc?.options?.[name]
        optFields[name] = spec.type === 'checkbox'
          ? field({ id: `device.option_${name.replace(/-/g, '_')}`, label: spec.label, type: 'checkbox', value: cur === 'true' })
          : field({ id: `device.option_${name.replace(/-/g, '_')}`, label: spec.label, type: 'select', value: cur || '', options: [{ value: '', label: 'Default' }, ...spec.choices.map(c => ({ value: c, label: c }))] })
        optWrap.append(optFields[name].el)
      }
    }
    paintOptions()
    kindField.input.addEventListener('change', () => { f.remote_port.set(DEFAULT_PORTS[kindField.get()]); paintOptions() })
    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form', novalidate: true, id: 'svc-form' }, msg, kindField.el, f.remote_port.el, f.username.el, f.password.el, clearPw?.el || null, optWrap)
    const save = button({ label: isNew ? 'Add service' : 'Save service', icon: 'action.save', variant: 'primary', type: 'submit' })
    save.setAttribute('form', 'svc-form')
    const d = drawer({ title: isNew ? 'Add a service' : `Edit ${serviceLabel(kind)}`, content: form,
      footer: h('div', { class: 'btn-row' }, button({ label: 'Cancel', variant: 'ghost', onClick: () => d.close() }), save) })
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      const port = f.remote_port.get()
      if (!Number.isInteger(port) || port < 1 || port > 65535) { f.remote_port.setError('Enter a port between 1 and 65535.'); f.remote_port.input.focus(); return }
      f.remote_port.setError('')
      const body = { remote_port: port, username: f.username.get().trim() }
      const pw = f.password.get()
      if (clearPw?.get()) body.password = ''
      else if (pw) body.password = pw
      const options = {}
      for (const [name, fl] of Object.entries(optFields)) {
        const v = fl.get()
        if (SERVICE_OPTIONS[name].type === 'checkbox') { if (v) options[name] = 'true' } else if (v) options[name] = v
      }
      body.options = options
      save.disabled = true
      try {
        const r = await api.put(`${path}/services/${kindField.get()}`, body)
        device = r.data
        f.password.set('')
        d.close()
        toast(isNew ? `${serviceLabel(kindField.get())} added` : `${serviceLabel(kindField.get())} saved`, { tone: 'success', detail: isNew ? 'The device picks up new services on its next reconnect.' : '' })
        activeTab = 'services'
        paint()
      } catch (err) {
        if (!applyFieldErrors(f, err)) replace(msg, formError(err))
      } finally { save.disabled = false }
    })
  }

  async function removeService(s) {
    const ok = await confirmDialog({ title: `Remove ${serviceLabel(s.kind)} from ${device.name}?`, body: 'Sessions using it end and the stored credential is deleted. You can add it again later.', confirmLabel: 'Remove', tone: 'danger' })
    if (!ok) return
    try {
      const r = await api.del(`${path}/services/${s.kind}`)
      device = r.data || { ...device, services: device.services.filter(x => x.kind !== s.kind) }
      toast(`${serviceLabel(s.kind)} removed`, { tone: 'success' })
      activeTab = 'services'
      paint()
    } catch (err) { toastError(err) }
  }

  /* ── sessions tab ── */

  function sessionsTab(panel) {
    const g = grid({
      label: `Sessions on ${device.name}`,
      helpScreen: 'sessions',
      emptyKey: 'device.sessions',
      exportName: `sessions-${device.name}`,
      initialSort: { id: 'started_at', dir: 'desc' },
      load: ({ pageToken, signal }) => api.get('/api/v1/sessions', { device_id: device.id, page_size: 50, page_token: pageToken }, { signal }),
      columns: [
        { id: 'service', label: 'Service', value: (s) => serviceLabel(s.service), render: (s) => h('span', { class: 'os' }, icon(`domain.service.${KINDS.includes(s.service) ? s.service : 'ssh'}`, { size: 'sm' }), serviceLabel(s.service)) },
        { id: 'user_email', label: 'User' },
        { id: 'started_at', label: 'Started', render: (s) => relTime(s.started_at) },
        { id: 'duration', label: 'Duration', value: (s) => between(s.started_at, s.ended_at), render: (s) => (s.active ? badge('Live', 'success') : duration(between(s.started_at, s.ended_at))) },
        { id: 'bytes', label: 'Traffic', align: 'end', value: (s) => (s.bytes_in || 0) + (s.bytes_out || 0), render: (s) => `${bytes(s.bytes_in)} in · ${bytes(s.bytes_out)} out` },
      ],
    })
    append(panel, g.el)
  }

  /* ── client logs tab ── */

  function logsTab(panel) {
    const out = h('div', { class: 'logview' })
    let timer = null
    let lines = []
    const load = async (quiet) => {
      if (!quiet) replace(out, skeleton('text', 6))
      try {
        const r = await api.get(`${path}/logs`)
        lines = r.data || []
        replace(out, lines.length
          ? h('pre', { class: 'logview__pre', tabindex: '0', 'aria-label': 'Client log lines' }, lines.map(l => h('span', { class: 'logline' },
            h('span', { class: 'logline__ts', title: absoluteTime(l.received_at) }, (l.received_at || '').slice(11, 19)), ' ', l.line, '\n')))
          : emptyState('device.logs'))
        const pre = out.querySelector('pre')
        if (pre) pre.scrollTop = pre.scrollHeight
      } catch (err) {
        if (!quiet) replace(out, errorState(err, () => load(false)))
      }
    }
    const auto = toggle({ label: 'Auto-refresh every 5 s', onChange: (on) => { clearInterval(timer); if (on) timer = setInterval(() => load(true), 5000) } })
    append(panel, 
      h('div', { class: 'section-head' },
        h('p', { class: 'muted' }, fieldHelp('device.client_logs')),
        h('div', { class: 'btn-row' }, auto.el,
          button({ label: 'Refresh', icon: 'action.refresh', variant: 'secondary', size: 'sm', onClick: () => load(false) }),
          copyButton(() => lines.map(l => `${l.received_at} ${l.line}`).join('\n'), { label: 'Copy all' }))),
      out)
    load(false)
    return () => clearInterval(timer)
  }

  /* ── diagnostics tab ── */

  function diagnosticsTab(panel) {
    const results = h('div', { class: 'probe' }, emptyState('device.probe', { action: null }))
    const runProbe = async () => {
      replace(results, skeleton('rows', 3))
      try {
        const r = await api.post(`${path}/probe`)
        const rows = r.data || []
        replace(results, grid({
          label: 'Probe results', helpScreen: 'device', emptyKey: 'device.probe', searchable: false, rows,
          rowKey: (x) => x.service,
          columns: [
            { id: 'service', label: 'Service', value: (x) => serviceLabel(x.service) },
            { id: 'ok', label: 'Result', value: (x) => (x.ok ? 'ok' : 'failed'), render: (x) => (x.ok ? badge('Reachable', 'success', 'status.success') : badge('Failed', 'danger', 'domain.status.fail')) },
            { id: 'banner', label: 'Banner', className: 'mono', render: (x) => x.banner || null },
            { id: 'latency_ms', label: 'Latency', align: 'end', render: (x) => (x.latency_ms != null ? durationMs(x.latency_ms) : null) },
            { id: 'hint', label: 'What to do', sortable: false, render: (x) => (x.ok ? null : h('span', { class: 'cell-stack' }, x.error ? h('span', { class: 'mono cell-sub' }, x.error) : null, x.hint || '')) },
          ],
        }).el)
      } catch (err) { replace(results, errorState(err, runProbe)) }
    }
    const debugSwitch = can('device.update') ? toggle({
      label: 'Debug logging for this device', checked: !!device.debug, describedBy: 'dbg-help',
      onChange: async (on, input) => {
        try {
          const r = await api.patch(path, { debug: on }, device.etag)
          device = r.data
          toast(on ? 'Debug logging on' : 'Debug logging off', { tone: 'success' })
        } catch (err) {
          input.checked = !on
          if (err.status === 412) { toast('The device changed meanwhile — reloading', { tone: 'warning' }); loadDevice() } else toastError(err)
        }
      },
    }) : null
    append(panel, 
      h('div', { class: 'diag-actions' },
        h('section', { class: 'card' }, h('h2', { class: 'card__title' }, 'Probe services'), h('p', { class: 'muted' }, fieldHelp('device.probe')),
          button({ label: 'Run probe', icon: 'domain.action.probe', variant: 'primary', permission: 'device.read', onClick: runProbe, busyLabel: 'Probing…', disabled: !device.online })),
        h('section', { class: 'card' }, h('h2', { class: 'card__title' }, 'Reconnect tunnel'), h('p', { class: 'muted' }, fieldHelp('device.reconnect')),
          button({ label: 'Ask device to reconnect', icon: 'domain.action.reconnect', variant: 'secondary', permission: 'device.update', disabled: !device.online,
            onClick: async () => {
              try { await api.post(`${path}/reconnect`); toast('Reconnect requested', { tone: 'success', detail: 'The device drops and re-opens its tunnel within a few seconds.' }) } catch (err) { toastError(err) }
            } })),
        debugSwitch ? h('section', { class: 'card' }, h('h2', { class: 'card__title' }, 'Debug logging'), h('p', { class: 'muted', id: 'dbg-help' }, fieldHelp('device.debug')), debugSwitch.el) : null),
      !device.online ? banner('info', 'The device is offline', describeError({ code: 'DEVICE_OFFLINE' }).fix) : null,
      results)
  }

  loadDevice()
  return root
}
