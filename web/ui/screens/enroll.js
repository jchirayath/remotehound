/**
 * Enroll (/enroll) — create a one-time enrolment code, show the command to type on the device,
 * and wait live until the device joins. Below: every code (open / used / expired) with revoke.
 *
 * Data: POST /api/v1/enrollments (the only response that carries `code` + commands);
 * GET /api/v1/enrollments/{id} polled every 3 s while waiting; GET /api/v1/enrollments for the list;
 * DELETE /enrollments/{id}.
 * The plain code lives only in this screen's memory — it is never stored in the browser.
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can, groups, groupMap } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import {
  page, field, button, linkButton, codeBlock, tabs, badge, grid, segmented, relTime, groupPill, confirmDialog,
  toast, toastError, applyFieldErrors, formError, banner, emptyState, deviceLink, drawer,
} from '../lib/ui.js'
import { countdown, toDate } from '../lib/format.js'

const TTLS = [[15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours'], [1440, '24 hours']]
const STATE_TONE = { open: 'info', used: 'success', expired: 'neutral' }
const OS_LABEL = { macos: 'macOS', linux: 'Linux', windows: 'Windows' }

export default function render(ctx) {
  const p = page({
    title: 'Enroll a device',
    subtitle: 'Create a one-time code, then type one short command on the machine you want to reach.',
    helpKey: 'enroll',
  })
  const wizard = h('section', { class: 'card enroll', 'aria-live': 'polite', 'aria-labelledby': 'enroll-h' })
  let listGrid = null
  let stopWaiting = () => {}
  ctx.onCleanup(() => stopWaiting())

  /* ── step 1: options ── */
  function stepCreate() {
    stopWaiting()
    if (!can('enrollment.create')) {
      replace(wizard, h('h2', { id: 'enroll-h', class: 'card__title' }, 'Enrolment codes'), banner('info', 'Your role cannot create codes', 'Ask an administrator or operator to enrol devices. You can still see the codes below.'))
      return
    }
    const f = {
      name: field({ id: 'enroll.name', label: 'Device name (optional)', maxlength: 64, placeholder: 'Uses the hostname if empty', value: String(ctx.query?.name || '').slice(0, 64) }),
      group_id: field({ id: 'enroll.group_id', label: 'Group', type: 'select', options: [{ value: '', label: 'Default group' }] }),
      expected_os: field({ id: 'enroll.expected_os', label: 'Machine type', type: 'select', value: '', options: [{ value: '', label: 'Any' }, { value: 'macos', label: 'macOS' }, { value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }] }),
      ttl_minutes: field({ id: 'enroll.ttl_minutes', label: 'Code valid for', type: 'select', value: '15', options: TTLS.map(([v, l]) => ({ value: String(v), label: l })) }),
    }
    groups().then(list => { for (const g of list) f.group_id.input.append(h('option', { value: g.id }, g.name)) })
      .catch(() => f.group_id.setError('Groups could not be loaded; the default group will be used.'))
    const msg = h('div', { class: 'form__msg' })
    const again = String(ctx.query?.name || '').slice(0, 64)
    if (again) replace(msg, banner('info', `Registering ${again} again`, 'Select Create code, then run the command it shows on that machine. After it joins, delete the old entry if it still exists.'))
    const form = h('form', { class: 'form', novalidate: true },
      h('h2', { id: 'enroll-h', class: 'card__title' }, h('span', { class: 'step-num', 'aria-hidden': 'true' }, '1'), 'Choose where the device goes'),
      msg,
      h('div', { class: 'form__grid' }, f.name.el, f.group_id.el, f.expected_os.el, f.ttl_minutes.el),
      h('div', { class: 'form__actions' }, button({ label: 'Create code', icon: 'domain.nav.enroll', variant: 'primary', type: 'submit', size: 'lg' })))
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      const body = { ttl_minutes: Number(f.ttl_minutes.get()) }
      if (f.name.get().trim()) body.name = f.name.get().trim()
      if (f.group_id.get()) body.group_id = f.group_id.get()
      if (f.expected_os.get()) body.expected_os = f.expected_os.get()
      const submit = form.querySelector('button[type=submit]')
      submit.disabled = true
      try {
        const r = await api.post('/api/v1/enrollments', body)
        stepWaiting(r.data)
        listGrid?.refresh()
      } catch (err) {
        if (!applyFieldErrors(f, err)) replace(msg, formError(err))
        submit.disabled = false
      }
    })
    replace(wizard, form)
    if (again) requestAnimationFrame(() => { wizard.scrollIntoView({ block: 'start', behavior: 'smooth' }); f.name.input.focus({ preventScroll: true }) })
  }

  /* ── step 2: show the code and wait ── */
  function stepWaiting(enr) {
    stopWaiting()
    const ctrl = new AbortController()
    const chars = String(enr.code || '').split('')
    const clock = h('span', { class: 'countdown__time', 'aria-live': 'off' }, countdown(enr.expires_at))
    const status = h('div', { class: 'waiting', role: 'status' },
      h('span', { class: 'waiting__pulse', 'aria-hidden': 'true' }),
      h('span', null, h('strong', null, 'Waiting for the device…'), h('span', { class: 'muted' }, ' This page updates by itself when it joins.')))
    // Both install types side by side; the person picks, the choice carries across the OS tabs.
    let scope = 'system'
    const scopeLabel = 'Install type'
    const scopeOptions = [
      { value: 'system', label: 'Permanent' },
      { value: 'user', label: 'Temporary' },
    ]
    function installChoice(panel, cmds) {
      const body = h('div', { class: 'cmd-body' })
      const draw = () => {
        const c = cmds[scope]
        replace(body,
          h('h3', { class: 'cmd-choice' }, scope === 'system' ? badge('Recommended', 'success') : null, ' ', c.title),
          h('p', { class: 'muted' }, fieldHelp(c.help)),
          codeBlock(c.command || '', { label: 'Copy command' }))
      }
      append(panel,
        h('div', { class: 'cmd-scope' }, h('span', { class: 'cmd-scope__label' }, scopeLabel),
          segmented({ label: scopeLabel, value: scope, options: scopeOptions, onChange: (v) => { scope = v; draw() } })),
        body)
      draw()
    }
    const cmdTabs = tabs({
      label: 'Operating system',
      tabs: [
        { id: 'unix', label: 'macOS / Linux', icon: 'domain.os.macos', render: (panel) => installChoice(panel, {
          system: { title: 'Permanent: the whole machine, starts at boot (sudo)', help: 'enroll.command_unix_system', command: enr.command_unix_system },
          user: { title: 'Temporary: just you, only while you are logged in (no sudo)', help: 'enroll.command_unix', command: enr.command_unix },
        }) },
        { id: 'windows', label: 'Windows PowerShell', icon: 'domain.os.windows', render: (panel) => installChoice(panel, {
          system: { title: 'Permanent: the whole machine, starts at boot (Run as administrator)', help: 'enroll.command_windows_system', command: enr.command_windows },
          user: { title: 'Temporary: just you, only while you are logged in (no administrator)', help: 'enroll.command_windows', command: enr.command_windows },
        }) },
      ],
      active: enr.expected_os === 'windows' ? 'windows' : enr.expected_os ? 'unix' : /Win/.test(navigator.platform || '') ? 'windows' : 'unix',
    })
    replace(wizard,
      h('h2', { id: 'enroll-h', class: 'card__title' }, h('span', { class: 'step-num', 'aria-hidden': 'true' }, '2'), 'Type this on the device'),
      h('div', { class: 'codehero' },
        h('div', { class: 'keycaps', role: 'img', 'aria-label': `Enrolment code ${chars.join(' ')}` }, chars.map(c => h('span', { class: 'keycap', 'aria-hidden': 'true' }, c))),
        h('div', { class: 'codehero__side' },
          h('p', { class: 'countdown' }, icon('domain.object.clock', { size: 'sm' }), 'Expires in ', clock),
          h('p', { class: 'muted' }, 'Single use. Shown only once — copy it now.'),
          enr.expected_os ? h('p', { class: 'muted' }, `Only a ${OS_LABEL[enr.expected_os]} machine can use it.`) : null,
          h('div', { class: 'btn-row' },
            button({ label: 'Copy code', icon: 'action.copy', variant: 'ghost', size: 'sm', onClick: () => navigator.clipboard.writeText(enr.code).then(() => toast('Code copied', { tone: 'success', timeout: 2000 }), () => toast('Copy failed — select the code manually', { tone: 'warning' })) }),
            can('enrollment.delete') ? button({ label: 'Revoke', icon: 'domain.action.revoke', variant: 'ghost', size: 'sm', onClick: async () => {
              if (!(await confirmDialog({ title: 'Revoke this code?', body: 'Anyone who has it can no longer enrol a device with it.', confirmLabel: 'Revoke', tone: 'danger' }))) return
              try { await api.del(`/api/v1/enrollments/${encodeURIComponent(enr.id)}`); toast('Code revoked', { tone: 'success' }); listGrid?.refresh(); stepCreate() } catch (err) { toastError(err) }
            } }) : null))),
      cmdTabs.el,
      status)

    const tick = setInterval(() => {
      clock.textContent = countdown(enr.expires_at)
      if ((toDate(enr.expires_at)?.getTime() || 0) <= Date.now()) { finish(); stepExpired() }
    }, 1000)
    let polling = false
    const poll = setInterval(async () => {
      if (polling || document.hidden) return
      polling = true
      try {
        const r = await api.get(`/api/v1/enrollments/${encodeURIComponent(enr.id)}`, null, { signal: ctrl.signal })
        const cur = r.data || {}
        if (cur.state === 'open') { status.classList.remove('is-degraded'); return }
        finish()
        if (cur.state === 'used' && cur.device_id) stepDone(cur)
        else stepExpired()
        listGrid?.refresh()
      } catch (err) {
        if (err?.name === 'AbortError') return
        if (err?.status === 404) { finish(); stepExpired(); listGrid?.refresh(); return } // revoked elsewhere
        status.classList.add('is-degraded')
      } finally { polling = false }
    }, 3000)
    function finish() { clearInterval(tick); clearInterval(poll); ctrl.abort() }
    stopWaiting = finish
  }

  function stepDone(enr) {
    replace(wizard, h('div', { class: 'success' },
      h('span', { class: 'success__mark', 'aria-hidden': 'true' }, icon('state.check', { size: 'xl' })),
      h('h2', { id: 'enroll-h', class: 'card__title', tabindex: '-1' }, `${enr.name || 'The device'} joined`),
      h('p', { class: 'muted' }, 'The tunnel is up. Open the device to connect or to add services.'),
      h('div', { class: 'btn-row' },
        linkButton({ href: `/devices/${encodeURIComponent(enr.device_id)}`, label: 'Open device', icon: 'domain.nav.devices', variant: 'primary' }),
        button({ label: 'Enroll another', icon: 'action.add', variant: 'secondary', onClick: stepCreate }))))
    wizard.querySelector('h2')?.focus()
  }

  function stepExpired() {
    replace(wizard, h('div', { class: 'success success--muted' },
      h('span', { class: 'success__mark', 'aria-hidden': 'true' }, icon('domain.object.clock', { size: 'xl' })),
      h('h2', { id: 'enroll-h', class: 'card__title' }, 'This code is no longer valid'),
      h('p', { class: 'muted' }, fieldHelp('enroll.expired')),
      button({ label: 'Create a new code', icon: 'action.refresh', variant: 'primary', onClick: stepCreate })))
  }

  /* ── code list ── */
  let gmap = new Map()
  let stateFilter = ctx.query?.state || ''
  listGrid = can('enrollment.read') ? grid({
    label: 'Enrolment codes',
    helpScreen: 'enroll',
    emptyKey: 'enroll.codes',
    exportName: 'enrolment-codes',
    query: { state: stateFilter },
    onClearFilters: () => { stateFilter = ''; listGrid.reload({ state: '' }) },
    initialSort: { id: 'created_at', dir: 'desc' },
    toolbar: h('div', { class: 'btn-row' },
      segmented({
        label: 'Code state', value: stateFilter,
        options: [{ value: '', label: 'All' }, { value: 'open', label: 'Open' }, { value: 'used', label: 'Used' }, { value: 'expired', label: 'Expired' }],
        onChange: (v) => { stateFilter = v; ctx.setQuery(v ? { state: v } : {}); listGrid.reload({ state: v }) },
      }),
      can('enrollment.delete') ? button({ label: 'Clear used & expired', icon: 'action.delete', variant: 'ghost', size: 'sm', onClick: clearOld }) : null),
    load: async ({ pageToken, query, signal }) => {
      gmap = await groupMap()
      return api.get('/api/v1/enrollments', { ...query, page_size: 50, page_token: pageToken }, { signal })
    },
    columns: [
      { id: 'code_hint', label: 'Code', className: 'mono', render: (e) => `••••${e.code_hint || ''}` },
      { id: 'name', label: 'Device name', render: (e) => e.name || h('span', { class: 'muted' }, 'From hostname') },
      { id: 'expected_os', label: 'For', value: (e) => OS_LABEL[e.expected_os] || 'Any', render: (e) => (e.expected_os ? OS_LABEL[e.expected_os] : h('span', { class: 'muted' }, 'Any')) },
      { id: 'group', label: 'Group', value: (e) => gmap.get(e.group_id)?.name || '', render: (e) => (e.group_id ? groupPill(gmap.get(e.group_id)) : h('span', { class: 'muted' }, 'Default')) },
      { id: 'state', label: 'State', render: (e) => badge(e.state, STATE_TONE[e.state] || 'neutral') },
      { id: 'expires_at', label: 'Expires / used', value: (e) => e.used_at || e.expires_at, render: (e) => (e.used_at ? relTime(e.used_at) : relTime(e.expires_at)) },
      { id: 'created_by', label: 'Created by', value: (e) => e.created_by_name || '', render: (e) => e.created_by_name || h('span', { class: 'muted' }, 'Another user') },
      { id: 'created_at', label: 'Created', render: (e) => relTime(e.created_at) },
      { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (e) => h('span', { class: 'btn-row btn-row--tight' },
        e.device_id ? deviceLink(e, 'Device') : null,
        e.state === 'open' && can('enrollment.create')
          ? button({ label: 'Edit', icon: 'action.edit', variant: 'ghost', size: 'sm', onClick: () => editCode(e) }) : null,
        can('enrollment.delete')
          ? button({ label: e.state === 'open' ? 'Revoke' : 'Delete', icon: e.state === 'open' ? 'domain.action.revoke' : 'action.delete', variant: 'ghost', size: 'sm', onClick: () => removeCode(e) })
          : null) },
    ],
  }) : null

  async function removeCode(e) {
    const open = e.state === 'open'
    const ok = await confirmDialog(open
      ? { title: `Revoke code ••••${e.code_hint || ''}?`, body: 'Anyone who has it can no longer enrol a device with it.', confirmLabel: 'Revoke', tone: 'danger' }
      : { title: `Delete this ${e.state} code?`, body: `Removes the ${e.name || 'unnamed'} code from this list.${e.device_id && !e.device_deleted ? ' The device it enrolled stays.' : ''}`, confirmLabel: 'Delete', tone: 'danger' })
    if (!ok) return
    try {
      await api.del(`/api/v1/enrollments/${encodeURIComponent(e.id)}`)
      toast(open ? 'Code revoked' : 'Code deleted', { tone: 'success' })
      listGrid.refresh()
    } catch (err) { toastError(err) }
  }

  async function clearOld() {
    const ok = await confirmDialog({ title: 'Clear used and expired codes?', body: 'Removes every used and expired code you can manage from this list. Open codes and enrolled devices are not affected.', confirmLabel: 'Clear', tone: 'danger' })
    if (!ok) return
    try {
      const r = await api.post('/api/v1/enrollments/cleanup')
      const n = r.data?.removed || 0
      toast(n ? `Removed ${n} code${n === 1 ? '' : 's'}` : 'Nothing to clear', { tone: 'success' })
      listGrid.refresh()
    } catch (err) { toastError(err) }
  }

  function editCode(e) {
    const f = {
      name: field({ id: 'enroll_edit.name', label: 'Device name (optional)', maxlength: 64, placeholder: 'Uses the hostname if empty', value: e.name || '' }),
      group_id: field({ id: 'enroll_edit.group_id', label: 'Group', type: 'select', options: [{ value: '', label: 'Default group' }] }),
      expected_os: field({ id: 'enroll_edit.expected_os', label: 'Machine type', type: 'select', value: e.expected_os || '', options: [{ value: '', label: 'Any' }, { value: 'macos', label: 'macOS' }, { value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }] }),
    }
    groups().then(list => {
      for (const g of list) f.group_id.input.append(h('option', { value: g.id }, g.name))
      f.group_id.input.value = e.group_id || ''
    }).catch(() => f.group_id.setError('Groups could not be loaded.'))
    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form', novalidate: true, id: 'enroll-edit-form' },
      h('p', { class: 'muted' }, `Code ••••${e.code_hint || ''} keeps working; only what it creates changes.`), msg, f.name.el, f.group_id.el, f.expected_os.el)
    const save = button({ label: 'Save', icon: 'action.save', variant: 'primary', type: 'submit' })
    save.setAttribute('form', 'enroll-edit-form')
    const d = drawer({ title: 'Edit enrolment code', content: form, footer: h('div', { class: 'btn-row' }, button({ label: 'Cancel', variant: 'ghost', onClick: () => d.close() }), save) })
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      save.disabled = true
      try {
        await api.patch(`/api/v1/enrollments/${encodeURIComponent(e.id)}`, { name: f.name.get().trim(), group_id: f.group_id.get(), expected_os: f.expected_os.get() })
        toast('Code updated', { tone: 'success' })
        d.close()
        listGrid.refresh()
      } catch (err) {
        if (!applyFieldErrors(f, err)) replace(msg, formError(err))
        save.disabled = false
      }
    })
  }

  stepCreate()
  append(p.body, wizard,
    h('section', { class: 'section', 'aria-labelledby': 'codes-h' },
      h('h2', { id: 'codes-h', class: 'section__title' }, 'Enrolment codes'),
      listGrid ? listGrid.el : emptyState('enroll.codes')))
  return p.el
}
