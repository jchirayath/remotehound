/**
 * Settings (/settings) — runtime behavior stored in the database (public address, enrollment,
 * sessions, recording, logging, retention, role mapping). Infrastructure settings (listeners,
 * secrets, identity provider) are environment config and are not shown here.
 *
 * Data: GET /api/v1/settings; PATCH (JSON Merge Patch, If-Match: etag) with only the changed fields.
 * Removed roles_map rows are sent as null (merge-patch delete). 412 → conflict banner + reload.
 */
import { h, replace, uid, append } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { can, groups } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import { page, field, button, iconButton, skeleton, errorState, toast, applyFieldErrors, formError, banner, confirmDialog } from '../lib/ui.js'
import { relativeTime } from '../lib/format.js'

/** Form layout: section title → field specs. `k` is the Settings property. */
export const SECTIONS = [
  ['Public address', 'How devices and browsers reach this server.', [
    { k: 'public_url', label: 'Public URL', type: 'url', mono: true, placeholder: 'https://rh.example.com' },
    { k: 'ssh_public_host', label: 'SSH tunnel host', mono: true, placeholder: 'rh.example.com' },
    { k: 'ssh_public_port', label: 'SSH tunnel port', type: 'number', min: 1, max: 65535, mono: true },
  ]],
  ['Enrollment and connections', 'Defaults for new devices and for opening sessions.', [
    { k: 'enrollment_ttl_minutes', label: 'Enrollment code lifetime', type: 'number', min: 5, max: 1440, suffix: 'minutes' },
    { k: 'connect_token_ttl_seconds', label: 'Connect link lifetime', type: 'number', min: 15, max: 600, suffix: 'seconds' },
    { k: 'default_group_id', label: 'Default group', type: 'group' },
    { k: 'vnc_enabled', label: 'Allow VNC connections', type: 'checkbox' },
  ]],
  ['Operator sessions', 'How long people stay signed in to RemoteHound.', [
    { k: 'session_idle_minutes', label: 'Sign out after inactivity', type: 'number', min: 5, max: 1440, suffix: 'minutes' },
    { k: 'session_absolute_hours', label: 'Maximum sign-in length', type: 'number', min: 1, max: 168, suffix: 'hours' },
  ]],
  ['Recording', 'Screen recordings of remote sessions, written by guacd.', [
    { k: 'recording_enabled', label: 'Record sessions', type: 'checkbox' },
    { k: 'recording_retention_days', label: 'Keep recordings for', type: 'number', min: 1, max: 3650, suffix: 'days' },
  ]],
  ['Logging and retention', 'What is logged and how long history is kept.', [
    { k: 'log_level', label: 'Default log level', type: 'select', options: ['DEBUG', 'INFO', 'WARN', 'ERROR'] },
    { k: 'client_logs_enabled', label: 'Collect device client logs', type: 'checkbox' },
    { k: 'audit_retention_days', label: 'Keep audit events for', type: 'number', min: 1, suffix: 'days' },
    { k: 'session_retention_days', label: 'Keep session history for', type: 'number', min: 1, suffix: 'days' },
  ]],
]

export default function render(ctx) {
  const writable = can('settings.write')
  const p = page({ title: 'Settings', subtitle: 'Behavior you can change without restarting the server.', helpKey: 'settings' })
  const body = h('div', { class: 'settings' }, skeleton('detail', 4))
  append(p.body, body)
  let current = null
  let fields = {}
  let roles = null

  async function load() {
    replace(body, skeleton('detail', 4))
    try {
      const r = await api.get('/api/v1/settings', null, { signal: ctx.signal })
      current = r.data
      paint()
    } catch (err) {
      if (err?.name !== 'AbortError') replace(body, errorState(err, load))
    }
  }

  function rolesEditor(map) {
    const rows = h('div', { class: 'kvedit', role: 'list' })
    const helpId = uid('roles-help')
    const addRow = (claim = '', role = 'viewer') => {
      const cId = uid('claim'), rId = uid('role')
      const claimIn = h('input', { id: cId, class: 'input input--mono', value: claim, placeholder: 'e.g. rh-admins', disabled: !writable, 'aria-describedby': helpId, onInput: sync })
      const roleSel = h('select', { id: rId, class: 'input input--select', disabled: !writable, onChange: sync }, ['admin', 'operator', 'viewer'].map(v => h('option', { value: v }, v)))
      roleSel.value = role
      const row = h('div', { class: 'kvedit__row', role: 'listitem' },
        h('div', { class: 'field' }, h('label', { class: 'field__label', for: cId }, 'Claim value'), claimIn),
        h('div', { class: 'field' }, h('label', { class: 'field__label', for: rId }, 'Role'), roleSel),
        writable ? iconButton({ icon: 'action.delete', label: 'Remove this mapping', onClick: () => { row.remove(); sync() } }) : null)
      row._get = () => [claimIn.value.trim(), roleSel.value]
      rows.append(row)
    }
    for (const [k, v] of Object.entries(map || {})) addRow(k, v)
    const err = h('p', { class: 'field__error', 'aria-live': 'polite' })
    const el = h('fieldset', { class: 'field' },
      h('legend', { class: 'field__label' }, 'Role mapping'),
      h('p', { class: 'field__help', id: helpId }, fieldHelp('settings.roles_map')),
      rows, err,
      writable ? button({ label: 'Add mapping', icon: 'action.add', variant: 'ghost', size: 'sm', onClick: () => { addRow(); sync(); rows.lastElementChild.querySelector('input').focus() } }) : null)
    return {
      el,
      get: () => Object.fromEntries([...rows.children].map(r => r._get()).filter(([k]) => k)),
      duplicate: () => { const ks = [...rows.children].map(r => r._get()[0]).filter(Boolean); return ks.length !== new Set(ks).size },
      setError: (m) => { err.textContent = m || '' },
      input: rows,
    }
  }

  const bar = h('div', { class: 'savebar', hidden: true, role: 'region', 'aria-label': 'Unsaved changes' })
  function changes() {
    const patch = {}
    for (const [k, f] of Object.entries(fields)) {
      const v = f.get()
      const was = current[k] ?? (f.input.type === 'checkbox' ? false : f.input.type === 'number' ? null : '')
      if (v !== was && !(v === '' && was === null)) patch[k] = v
    }
    const map = roles.get()
    const before = current.roles_map || {}
    const diff = {}
    for (const [k, v] of Object.entries(map)) if (before[k] !== v) diff[k] = v
    for (const k of Object.keys(before)) if (!(k in map)) diff[k] = null
    if (Object.keys(diff).length) patch.roles_map = diff
    return patch
  }
  function sync() {
    if (!current || !roles) return
    const n = Object.keys(changes()).length
    bar.hidden = n === 0
    bar.querySelector('.savebar__count').textContent = `${n} unsaved ${n === 1 ? 'change' : 'changes'}`
  }

  function paint() {
    fields = {}
    const msg = h('div', { class: 'form__msg' })
    const sections = SECTIONS.map(([title, desc, specs]) => h('section', { class: 'card settings__section', 'aria-labelledby': `s-${specs[0].k}` },
      h('div', { class: 'settings__intro' }, h('h2', { id: `s-${specs[0].k}`, class: 'card__title' }, title), h('p', { class: 'muted' }, desc)),
      h('div', { class: 'settings__fields' }, specs.map(s => {
        const f = field({
          id: `settings.${s.k}`, label: s.label, type: s.type === 'group' ? 'select' : s.type || 'text', value: current[s.k], min: s.min, max: s.max,
          mono: s.mono, placeholder: s.placeholder, suffix: s.suffix, disabled: !writable, onInput: sync,
          options: s.type === 'select' ? s.options.map(o => ({ value: o, label: o })) : s.type === 'group' ? [{ value: '', label: 'No default group' }] : undefined,
        })
        if (s.type === 'group') {
          groups().then(list => { for (const g of list) f.input.append(h('option', { value: g.id }, g.name)); f.set(current[s.k] || '') })
            .catch(() => f.setError('Groups could not be loaded.'))
        }
        fields[s.k] = f
        return f.el
      }))))
    const rf = field({ id: 'settings.roles_claim', label: 'Role claim', value: current.roles_claim || '', mono: true, placeholder: 'groups', disabled: !writable, onInput: sync })
    fields.roles_claim = rf
    roles = rolesEditor(current.roles_map)
    sections.push(h('section', { class: 'card settings__section', 'aria-labelledby': 's-roles' },
      h('div', { class: 'settings__intro' }, h('h2', { id: 's-roles', class: 'card__title' }, 'Sign-in roles'), h('p', { class: 'muted' }, 'Give people a role automatically from a claim your identity provider sends.')),
      h('div', { class: 'settings__fields' }, rf.el, roles.el)))

    replace(bar,
      h('span', { class: 'savebar__count' }),
      h('div', { class: 'btn-row' },
        button({ label: 'Discard', variant: 'ghost', onClick: async () => { if (await confirmDialog({ title: 'Discard your changes?', confirmLabel: 'Discard', tone: 'danger' })) paint() } }),
        button({ label: 'Save changes', icon: 'action.save', variant: 'primary', onClick: save })))
    bar.hidden = true

    async function save() {
      replace(msg)
      if (roles.duplicate()) { roles.setError('Each claim value can map to one role only.'); return }
      roles.setError('')
      const patch = changes()
      if (!Object.keys(patch).length) return
      try {
        const r = await api.patch('/api/v1/settings', patch, current.etag)
        current = r.data
        toast('Settings saved', { tone: 'success' })
        paint()
      } catch (err) {
        if (err.status === 412) replace(msg, banner('warning', 'Settings were changed by someone else', 'Your changes were not saved. Reload to see the latest values, then make your change again.', button({ label: 'Reload', icon: 'action.refresh', variant: 'secondary', onClick: load })))
        else if (!applyFieldErrors(fields, err)) replace(msg, formError(err))
        msg.scrollIntoView({ block: 'nearest' })
      }
    }

    replace(body,
      !writable ? banner('info', 'Read only', 'Your role can view settings but not change them.') : null,
      current.updated_at ? h('p', { class: 'muted settings__updated' }, `Last changed ${relativeTime(current.updated_at)}`) : null,
      msg, sections, bar)
  }

  load()
  return p.el
}
