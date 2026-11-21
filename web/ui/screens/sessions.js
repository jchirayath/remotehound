/**
 * Sessions (/sessions) — your live sessions, sessions shared with you, every session (admins, view
 * only), history and recordings. Join / Share / End buttons appear strictly from the per-session flags
 * the server returns (can_join, can_share, can_terminate); the UI never infers them from the role.
 *
 * Data: GET /api/v1/sessions?scope=mine|shared&active=true|false (no scope = every session, for
 * session.read_all); POST /sessions/{id}/join → {url}; POST/DELETE /sessions/{id}/shares[/{user_id}];
 * POST /sessions/{id}/terminate; GET /api/v1/directory?q= (share picker); GET /api/v1/recordings.
 */
import { h, replace, append, uid } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import { openSession } from '../lib/connect.js'
import {
  page, tabs, grid, button, badge, relTime, confirmDialog, toast, toastError, linkButton, toggle, drawer, field,
  formError, applyFieldErrors, banner, skeleton, errorState, iconButton, deviceLink,
} from '../lib/ui.js'
import { serviceLabel, bytes, duration, between, absoluteTime, SHARE_DURATIONS, shareDuration, shareModeLabel } from '../lib/format.js'

const svc = (s) => h('span', { class: 'os' }, icon(`domain.service.${['ssh', 'rdp', 'vnc'].includes(s.service) ? s.service : 'ssh'}`, { size: 'sm' }), serviceLabel(s.service))
const device = (s) => deviceLink(s)
const traffic = (s) => `${bytes(s.bytes_in)} in · ${bytes(s.bytes_out)} out`

/** Badges capitalise each word by default; sentence-case ones keep their text as written. */
const sentence = (el) => { el.classList.add('badge--sentence'); return el }

/** Owner cell: "You" for your own sessions, plus the "Shared with you" badge from my_share. */
function owner(s) {
  const shares = s.shares || []
  return h('span', { class: 'cell-stack' },
    h('span', null, s.mine ? 'You' : (s.user_email || s.user_id || 'Unknown')),
    s.my_share ? sentence(badge(`Shared with you · ${shareModeLabel(s.my_share.mode).toLowerCase()}`, s.my_share.mode === 'control' ? 'brand' : 'info', s.my_share.mode === 'control' ? 'domain.share.control' : 'state.visibility')) : null,
    shares.length ? h('span', { class: 'cell-sub' }, s.mine ? `shared with ${shares.map(x => x.user_email || x.user_id).join(', ')}` : `shared with ${shares.length}`) : null)
}

export default function render(ctx) {
  const p = page({
    title: 'Sessions',
    subtitle: 'Your remote sessions, the ones shared with you, and their history.',
    helpKey: 'sessions',
  })

  /** Join / Share / End — strictly from the server's flags. */
  function actions(s, refresh) {
    return h('span', { class: 'btn-row btn-row--tight' },
      s.can_join ? button({ label: 'Join', icon: 'domain.action.join', variant: 'primary', size: 'sm',
        onClick: (ev) => openSession(() => api.post(`/api/v1/sessions/${encodeURIComponent(s.id)}/join`),
          { what: `${s.user_email ? `${s.user_email}’s` : 'the'} session on ${s.device_name || 'the device'}`, button: ev.currentTarget }) }) : null,
      s.can_share ? button({ label: 'Share', icon: 'action.share', variant: 'secondary', size: 'sm', onClick: () => shareDrawer(s, refresh) }) : null,
      s.can_terminate ? button({ label: 'End', icon: 'domain.action.disable', variant: 'danger', size: 'sm', onClick: () => endSession(s, refresh) }) : null)
  }

  async function endSession(s, refresh) {
    const others = !s.mine
    const ok = await confirmDialog({
      title: others ? `End ${s.user_email || 'this user'}’s session?` : `End your ${serviceLabel(s.service)} session?`,
      body: others
        ? `This ends ${s.user_email || 'the owner'}’s ${serviceLabel(s.service)} session on ${s.device_name || 'the device'} immediately, for everyone joined to it. Ending someone else’s session is recorded in the audit log with your name.`
        : `Your session on ${s.device_name || 'the device'} ends now${(s.shares || []).length ? ', and everyone you shared it with is disconnected' : ''}.`,
      confirmLabel: 'End session', tone: 'danger',
    })
    if (!ok) return
    try {
      await api.post(`/api/v1/sessions/${encodeURIComponent(s.id)}/terminate`)
      toast('Session ended', { tone: 'success' })
      refresh()
    } catch (err) { toastError(err) }
  }

  /* ── share drawer ── */
  function shareDrawer(s, refresh) {
    let shares = [...(s.shares || [])]
    let picked = null
    const results = h('div', { class: 'picker__results', role: 'radiogroup', 'aria-label': 'People' })
    const pickerErr = h('p', { class: 'field__error', 'aria-live': 'polite' })
    const qId = uid('dir-q')
    const q = h('input', { id: qId, type: 'search', class: 'input', placeholder: 'Search by name or email', autocomplete: 'off', 'aria-describedby': `${qId}-help`, maxlength: 100 })
    const pickerName = uid('person')

    const modeName = uid('mode')
    const viewId = uid('mode-v'), ctlId = uid('mode-c')
    const viewIn = h('input', { type: 'radio', name: modeName, id: viewId, value: 'view', checked: true, class: 'segmented__input' })
    const ctlIn = h('input', { type: 'radio', name: modeName, id: ctlId, value: 'control', class: 'segmented__input' })
    const modeHelp = h('p', { class: 'field__help', id: uid('mode-help') }, fieldHelp('sessions.share_mode'))
    const modeField = h('fieldset', { class: 'field', 'aria-describedby': modeHelp.id },
      h('legend', { class: 'field__label' }, 'Access'),
      h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': 'Access' },
        viewIn, h('label', { for: viewId, class: 'segmented__opt' }, icon('state.visibility', { size: 'sm' }), 'View only'),
        ctlIn, h('label', { for: ctlId, class: 'segmented__opt' }, icon('domain.share.control', { size: 'sm' }), 'Control')),
      modeHelp)
    const ttl = field({ id: 'sessions.share_ttl', label: 'For', type: 'select', value: '60', options: SHARE_DURATIONS.map(m => ({ value: String(m), label: shareDuration(m) })) })

    const syncMode = () => {
      const viewer = picked?.role === 'viewer'
      ctlIn.disabled = viewer
      if (viewer) { ctlIn.checked = false; viewIn.checked = true }
      modeHelp.textContent = viewer ? fieldHelp('sessions.share_viewer') : fieldHelp('sessions.share_mode')
    }

    let seq = 0
    let timer = null
    async function search() {
      const mine = ++seq
      replace(results, skeleton('rows', 2))
      try {
        const r = await api.get('/api/v1/directory', { q: q.value.trim() })
        if (mine !== seq) return
        const people = (r.data || []).filter(u => !shares.some(x => x.user_id === u.id))
        if (!people.length) { replace(results, h('p', { class: 'muted picker__empty' }, q.value.trim() ? 'Nobody matches that search.' : 'There is nobody else to share with yet.')); return }
        replace(results, people.slice(0, 50).map(u => {
          const id = uid('pp')
          const input = h('input', { type: 'radio', name: pickerName, id, value: u.id, class: 'picker__input', checked: picked?.id === u.id })
          input.addEventListener('change', () => { picked = u; pickerErr.textContent = ''; syncMode() })
          return h('label', { class: 'picker__item', for: id }, input,
            h('span', { class: 'user__avatar', 'aria-hidden': 'true' }, (u.display_name || u.email || '?').slice(0, 1).toUpperCase()),
            h('span', { class: 'picker__text' }, h('span', { class: 'picker__name' }, u.display_name || u.email), u.display_name ? h('span', { class: 'cell-sub' }, u.email) : null),
            badge(u.role, u.role === 'viewer' ? 'neutral' : 'info'))
        }))
      } catch (err) {
        if (mine === seq) replace(results, errorState(err, search))
      }
    }
    q.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(search, 250) })

    const current = h('div', { class: 'shares' })
    function paintShares() {
      replace(current, shares.length
        ? h('ul', { class: 'shares__list', role: 'list' }, shares.map(x => h('li', { class: 'shares__item' },
          h('span', { class: 'picker__text' }, h('span', { class: 'picker__name' }, x.user_email || x.user_id),
            h('span', { class: 'cell-sub' }, shareModeLabel(x.mode), x.expires_at ? [' · until ', h('time', { datetime: x.expires_at, title: absoluteTime(x.expires_at) }, absoluteTime(x.expires_at))] : null)),
          iconButton({ icon: 'action.delete', label: `Stop sharing with ${x.user_email || x.user_id}`, onClick: async () => {
            try {
              await api.del(`/api/v1/sessions/${encodeURIComponent(s.id)}/shares/${encodeURIComponent(x.user_id)}`)
              shares = shares.filter(y => y.user_id !== x.user_id)
              toast(`Stopped sharing with ${x.user_email || 'that person'}`, { tone: 'success' })
              paintShares()
              refresh()
            } catch (err) { toastError(err) }
          } }))))
        : h('p', { class: 'muted' }, 'Not shared with anyone yet.'))
    }
    paintShares()

    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form', novalidate: true, id: 'share-form' },
      h('p', { class: 'muted' }, fieldHelp('sessions.share')),
      msg,
      h('div', { class: 'field' },
        h('label', { class: 'field__label', for: qId }, 'Person'),
        q, h('p', { class: 'field__help', id: `${qId}-help` }, fieldHelp('sessions.share_user')),
        results, pickerErr),
      modeField, ttl.el,
      h('section', { class: 'help__section' }, h('h3', { class: 'help__h' }, 'Currently shared with'), current))
    const save = button({ label: 'Share session', icon: 'action.share', variant: 'primary', type: 'submit' })
    save.setAttribute('form', 'share-form')
    const d = drawer({ title: `Share ${serviceLabel(s.service)} on ${s.device_name || 'device'}`, content: form,
      footer: h('div', { class: 'btn-row' }, button({ label: 'Close', variant: 'ghost', onClick: () => d.close() }), save),
      onClose: () => clearTimeout(timer) })
    q.focus()
    search()

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      if (!picked) { pickerErr.textContent = 'Choose the person to share with.'; q.focus(); return }
      const body = { user_id: picked.id, mode: ctlIn.checked ? 'control' : 'view', ttl_minutes: Number(ttl.get()) }
      save.disabled = true
      try {
        const r = await api.post(`/api/v1/sessions/${encodeURIComponent(s.id)}/shares`, body)
        const added = r.data?.user_id ? r.data : { user_id: picked.id, user_email: picked.email, mode: body.mode, expires_at: new Date(Date.now() + body.ttl_minutes * 60000).toISOString() }
        shares = shares.filter(x => x.user_id !== added.user_id).concat(added)
        toast(`Shared with ${picked.display_name || picked.email}`, { tone: 'success', detail: `${shareModeLabel(body.mode)} for ${shareDuration(body.ttl_minutes)}. They see it under Shared with me.` })
        picked = null
        syncMode()
        paintShares()
        search()
        refresh()
      } catch (err) {
        if (!applyFieldErrors({ ttl_minutes: ttl }, err)) replace(msg, formError(err))
      } finally { save.disabled = false }
    })
  }

  /* ── live lists ── */
  function liveTab(scope, emptyKey, label, { viewOnlyNote = false } = {}) {
    return (panel) => {
      let live = true
      const g = grid({
        label,
        helpScreen: 'sessions',
        emptyKey,
        exportName: `sessions-${scope || 'all'}`,
        initialSort: { id: 'started_at', dir: 'desc' },
        load: ({ pageToken, signal }) => api.get('/api/v1/sessions', { scope, active: true, page_size: 100, page_token: pageToken }, { signal }),
        columns: [
          { id: 'device_name', label: 'Device', primary: true, render: device },
          { id: 'service', label: 'Service', value: (s) => serviceLabel(s.service), render: svc },
          { id: 'owner', label: 'Owner', value: (s) => (s.mine ? 'you' : s.user_email), render: owner },
          { id: 'started_at', label: 'Started', render: (s) => relTime(s.started_at) },
          { id: 'duration', label: 'Duration', value: (s) => between(s.started_at), render: (s) => duration(between(s.started_at)) },
          { id: 'bytes', label: 'Traffic', align: 'end', value: (s) => (s.bytes_in || 0) + (s.bytes_out || 0), render: traffic },
          { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (s) => actions(s, () => g.refresh()) },
        ],
        toolbar: toggle({ label: 'Live (every 5 s)', checked: true, onChange: (on) => { live = on } }).el,
      })
      const t = setInterval(() => { if (live && !document.hidden) g.refresh() }, 5000)
      append(panel, viewOnlyNote ? banner('info', 'View only', fieldHelp('sessions.all_view_only')) : null, g.el)
      return () => clearInterval(t)
    }
  }

  function segmentedScope(onChange) {
    const name = uid('scope')
    const el = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': 'Whose sessions' })
    for (const [v, l] of [['mine', 'Mine'], ['', 'Everyone']]) {
      const id = uid('scope-o')
      const input = h('input', { type: 'radio', name, id, value: v, checked: v === 'mine', class: 'segmented__input' })
      input.addEventListener('change', () => onChange(v))
      append(el, input, h('label', { for: id, class: 'segmented__opt' }, l))
    }
    return el
  }

  function historyTab(panel) {
    const all = can('session.read_all')
    let scope = 'mine'
    const g = grid({
      label: 'Session history',
      helpScreen: 'sessions',
      emptyKey: 'sessions.history',
      exportName: 'session-history',
      initialSort: { id: 'started_at', dir: 'desc' },
      load: ({ pageToken, signal }) => api.get('/api/v1/sessions', { scope: scope || undefined, active: false, page_size: 100, page_token: pageToken }, { signal }),
      toolbar: all ? h('div', { class: 'filter' }, h('span', { class: 'filter__label', 'aria-hidden': 'true' }, 'Show'), segmentedScope((v) => { scope = v; g.reload({}) })) : null,
      columns: [
        { id: 'device_name', label: 'Device', primary: true, render: device },
        { id: 'service', label: 'Service', value: (s) => serviceLabel(s.service), render: svc },
        { id: 'owner', label: 'Owner', value: (s) => (s.mine ? 'you' : s.user_email), render: owner },
        { id: 'started_at', label: 'Started', value: (s) => s.started_at, render: (s) => h('time', { datetime: s.started_at, title: absoluteTime(s.started_at) }, absoluteTime(s.started_at)) },
        { id: 'duration', label: 'Duration', value: (s) => between(s.started_at, s.ended_at), render: (s) => duration(between(s.started_at, s.ended_at)) },
        { id: 'bytes', label: 'Traffic', align: 'end', value: (s) => (s.bytes_in || 0) + (s.bytes_out || 0), render: traffic },
        { id: 'recording', label: 'Recording', render: (s) => (s.recording && can('recording.read') ? h('a', { class: 'link', href: api.url(`/api/v1/recordings/${encodeURIComponent(s.recording)}`), download: s.recording }, 'Download') : null) },
      ],
    })
    append(panel, g.el)
  }

  function recordingsTab(panel) {
    const g = grid({
      label: 'Recordings',
      helpScreen: 'sessions',
      emptyKey: 'sessions.recordings',
      exportName: 'recordings',
      rowKey: (r) => r.name,
      initialSort: { id: 'modified_at', dir: 'desc' },
      load: ({ signal }) => api.get('/api/v1/recordings', null, { signal }),
      columns: [
        { id: 'name', label: 'File', primary: true, className: 'mono' },
        { id: 'size_bytes', label: 'Size', align: 'end', render: (r) => bytes(r.size_bytes) },
        { id: 'modified_at', label: 'Recorded', render: (r) => relTime(r.modified_at) },
        { id: 'download', label: 'Download', sortable: false, exportable: false, help: false, render: (r) => linkButton({ href: api.url(`/api/v1/recordings/${encodeURIComponent(r.name)}`), label: 'Download', icon: 'action.export', variant: 'ghost', size: 'sm', download: r.name }) },
      ],
    })
    append(panel, g.el)
  }

  const t = tabs({
    label: 'Session views',
    active: ctx.query?.tab || 'mine',
    onChange: (id) => ctx.setQuery(id === 'mine' ? {} : { tab: id }),
    tabs: [
      { id: 'mine', label: 'Mine', icon: 'domain.object.radio', render: liveTab('mine', 'sessions.mine', 'My live sessions') },
      { id: 'shared', label: 'Shared with me', icon: 'action.share', render: liveTab('shared', 'sessions.shared', 'Sessions shared with me') },
      can('session.read_all') ? { id: 'all', label: 'All sessions (view only)', icon: 'object.users', render: liveTab(undefined, 'sessions.all', 'All live sessions', { viewOnlyNote: true }) } : null,
      { id: 'history', label: 'History', icon: 'object.calendar', render: historyTab },
      can('recording.read') ? { id: 'recordings', label: 'Recordings', icon: 'object.document', render: recordingsTab } : null,
    ].filter(Boolean),
  })
  append(p.body, t.el)
  return p.el
}
