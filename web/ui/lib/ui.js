/**
 * UI primitives (CORE-11). Screens compose these; they never hand-roll tables, states or dialogs.
 *
 * Exports (all return DOM nodes or small controller objects):
 *  Page chrome     page({title, subtitle, helpKey, actions, back, eyebrow}) → {el, body}
 *  States (UX-1)   skeleton(kind), emptyState(key, overrides), errorState(err, onRetry), load(container, opts)
 *  Brand           mascot(state) — the hound artwork (decorative, CSS background from /ui/brand/)
 *  Data grid       grid(opts) → {el, reload(query), refresh(), rows()}  — filter, sort, cursor paging,
 *                  column ⓘ help, CSV/JSON export, drill-down, stacked cards on compact widths
 *  Controls        button, iconButton, linkButton, copyButton, tabs, segmented, toggle
 *  Forms           field(spec) → {el, input, get, set, setError}, applyFieldErrors(fields, err), formError(err)
 *  Display         badge, presenceDot, groupPill, serviceChip, osIcon, relTime, statCard, kv, codeBlock
 *  Overlays        drawer, confirmDialog, toast (from overlay.js), toastError(err, fallback)
 *
 * Help text, empty-state copy and error fixes come from the help registry (help.js) — never inline.
 * Colours/spacing come only from tokens via classes in app.css.
 */
import { h, append, replace, uid } from './dom.js'
import { icon } from './icons.js'
import { fieldHelp, columnHelp, emptyHelp, errorHelp, openHelp, openDoc } from './help.js'
import { relativeTime, dateTimeTitle, osLabel, serviceLabel, csvCell } from './format.js'
import { drawer, confirmDialog, toast } from './overlay.js'
import { can } from './session.js'
import { log } from './log.js'

export { drawer, confirmDialog, toast }

/* ───────────────────────── page chrome ───────────────────────── */

/**
 * @param {{title:string, subtitle?:string|Node, helpKey:string, actions?:Array<Node|null>, back?:{href:string,label:string}, lead?:Node}} o
 * @returns {{el:HTMLElement, body:HTMLElement, header:HTMLElement}}
 */
export function page(o) {
  const body = h('div', { class: 'page__body' })
  const header = h('header', { class: 'page__header' },
    h('div', { class: 'page__heading' },
      o.back ? h('a', { class: 'page__back', href: o.back.href }, icon('action.back', { size: 'sm' }), o.back.label) : null,
      h('div', { class: 'page__titlerow' },
        o.lead || null,
        h('h1', { class: 'page__title', tabindex: '-1' }, o.title),
        helpButton(o.helpKey)),
      o.subtitle ? h('p', { class: 'page__subtitle' }, o.subtitle) : null),
    o.actions?.length ? h('div', { class: 'page__actions' }, o.actions) : null)
  const el = h('div', { class: 'page' }, header, body)
  return { el, body, header }
}

/** The consistent `?` affordance (HELP-1). */
export function helpButton(key, label = 'Help for this screen') {
  return h('button', { type: 'button', class: 'btn btn--ghost btn--icon help-btn', 'aria-label': label, title: `${label} (?)`, onClick: () => openHelp(key) }, icon('nav.help'))
}

/* ───────────────────────── controls ───────────────────────── */

/**
 * @param {{label:string, icon?:string, variant?:'primary'|'secondary'|'ghost'|'danger'|'accent', onClick?:Function,
 *          disabled?:boolean, title?:string, size?:'sm'|'lg', type?:string, permission?:string, busyLabel?:string, className?:string}} o
 *  permission: hides the button when the user lacks it (UX only).
 *  onClick may return a Promise; the button shows a busy state until it settles.
 */
export function button(o) {
  if (o.permission && !can(o.permission)) return null
  const label = h('span', { class: 'btn__label' }, o.label)
  const b = h('button', {
    type: o.type || 'button',
    class: ['btn', `btn--${o.variant || 'secondary'}`, o.size && `btn--${o.size}`, o.className],
    disabled: o.disabled, title: o.title,
  }, o.icon ? icon(o.icon, { size: o.size === 'lg' ? 'lg' : 'md' }) : null, label)
  if (o.onClick) {
    b.addEventListener('click', async (ev) => {
      const r = o.onClick(ev)
      if (r && typeof r.then === 'function') {
        b.disabled = true
        b.setAttribute('aria-busy', 'true')
        const prev = label.textContent
        if (o.busyLabel) label.textContent = o.busyLabel
        try { await r } finally {
          b.disabled = !!o.disabled
          b.removeAttribute('aria-busy')
          label.textContent = prev
        }
      }
    })
  }
  return b
}

/** Icon-only button with a required accessible label. */
export function iconButton({ icon: name, label, onClick, variant = 'ghost', permission, size, disabled, pressed }) {
  if (permission && !can(permission)) return null
  return h('button', {
    type: 'button', class: ['btn', `btn--${variant}`, 'btn--icon', size && `btn--${size}`], 'aria-label': label, title: label,
    onClick, disabled, 'aria-pressed': pressed === undefined ? null : String(!!pressed),
  }, icon(name, { size: size === 'sm' ? 'sm' : 'md' }))
}

/** An <a> styled as a button (navigation, downloads). */
export function linkButton({ href, label, icon: name, variant = 'secondary', download, newTab, permission, size }) {
  if (permission && !can(permission)) return null
  return h('a', {
    href, class: ['btn', `btn--${variant}`, size && `btn--${size}`], download: download || null,
    target: newTab ? '_blank' : null, rel: newTab ? 'noopener noreferrer' : null,
  }, name ? icon(name) : null, h('span', { class: 'btn__label' }, label))
}

/**
 * A device name that links to its page. When the device has since been deleted (rows from
 * sessions, saved logins and enrolment codes carry `device_deleted`), it links to Enroll instead,
 * with the old name filled in, so the machine can be registered again.
 * @param {{device_id:string, device_name?:string, name?:string, device_deleted?:boolean}} row
 * @param {string} [label] link text for a live device (default: its name)
 */
export function deviceLink(row, label) {
  if (row.device_deleted) {
    const name = String(row.name || row.device_name || '').replace(/\s*\(deleted device\)$/, '').trim()
    return h('a', { href: name ? `/enroll?name=${encodeURIComponent(name)}` : '/enroll', class: 'link', title: 'This device was deleted. Register the machine again to reach it.' },
      name ? `${name} (removed) · register again` : 'Removed device · register again')
  }
  return h('a', { href: `/devices/${encodeURIComponent(row.device_id)}`, class: 'link' }, label || row.device_name || row.device_id)
}

/**
 * Copy-to-clipboard button. Announces the result via a toast.
 * @param {string|(() => string)} text
 * @param {{label?:string, compact?:boolean, variant?:string}} [o]
 */
export function copyButton(text, o = {}) {
  const label = o.label || 'Copy'
  const b = h('button', { type: 'button', class: ['btn', `btn--${o.variant || 'secondary'}`, o.compact && 'btn--icon', 'copy-btn'], 'aria-label': o.compact ? label : null, title: label },
    icon('action.copy'), o.compact ? null : h('span', { class: 'btn__label' }, label))
  b.addEventListener('click', async () => {
    const value = typeof text === 'function' ? text() : text
    try {
      await navigator.clipboard.writeText(value)
      b.classList.add('is-copied')
      b.replaceChild(icon('state.check'), b.firstChild)
      setTimeout(() => { b.classList.remove('is-copied'); b.replaceChild(icon('action.copy'), b.firstChild) }, 1600)
      toast('Copied to clipboard', { tone: 'success', timeout: 2000 })
    } catch (e) {
      log.warn('clipboard.failed', { reason: e?.name })
      toast('Copy failed — select the text and copy it manually', { tone: 'warning' })
    }
  })
  return b
}

/**
 * Tabs (WAI-ARIA tabs pattern with arrow-key navigation).
 * @param {{tabs:Array<{id:string,label:string,icon?:string,render:(panel:HTMLElement)=>void|(()=>void)}>, active?:string, onChange?:(id:string)=>void, label:string}} o
 * @returns {{el:HTMLElement, select:(id:string)=>void}}
 */
export function tabs(o) {
  const base = uid('tabs')
  const list = h('div', { class: 'tabs__list', role: 'tablist', 'aria-label': o.label })
  const panel = h('div', { class: 'tabs__panel', role: 'tabpanel', tabindex: '0' })
  let cleanup = null
  const btns = o.tabs.map(t => h('button', {
    type: 'button', role: 'tab', id: `${base}-${t.id}`, class: 'tabs__tab', 'aria-controls': `${base}-panel`,
    onClick: () => select(t.id),
    onKeydown: (ev) => {
      const i = o.tabs.findIndex(x => x.id === t.id)
      let j = null
      if (ev.key === 'ArrowRight') j = (i + 1) % o.tabs.length
      if (ev.key === 'ArrowLeft') j = (i - 1 + o.tabs.length) % o.tabs.length
      if (ev.key === 'Home') j = 0
      if (ev.key === 'End') j = o.tabs.length - 1
      if (j !== null) { ev.preventDefault(); select(o.tabs[j].id); btns[j].focus() }
    },
  }, t.icon ? icon(t.icon, { size: 'sm' }) : null, t.label))
  panel.id = `${base}-panel`
  append(list, btns)
  function select(id) {
    const t = o.tabs.find(x => x.id === id) || o.tabs[0]
    btns.forEach((b, i) => {
      const on = o.tabs[i].id === t.id
      b.setAttribute('aria-selected', String(on))
      b.tabIndex = on ? 0 : -1
    })
    panel.setAttribute('aria-labelledby', `${base}-${t.id}`)
    if (typeof cleanup === 'function') cleanup()
    replace(panel)
    cleanup = t.render(panel) || null
    o.onChange?.(t.id)
  }
  const el = h('div', { class: 'tabs' }, h('div', { class: 'tabs__scroller' }, list), panel)
  select(o.active || o.tabs[0].id)
  el.addEventListener('rh:unmount', () => { if (typeof cleanup === 'function') cleanup() })
  return { el, select }
}

/**
 * Segmented control (radio group).
 * @param {{label:string, options:Array<{value:string,label:string,icon?:string}>, value:string, onChange:(v:string)=>void|Promise<void>, disabled?:boolean}} o
 */
export function segmented(o) {
  const name = uid('seg')
  const el = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': o.label })
  for (const opt of o.options) {
    const id = uid('seg-opt')
    const input = h('input', { type: 'radio', name, id, value: opt.value, checked: opt.value === o.value, disabled: o.disabled, class: 'segmented__input' })
    input.addEventListener('change', () => o.onChange(opt.value))
    append(el, [input, h('label', { for: id, class: 'segmented__opt' }, opt.icon ? icon(opt.icon, { size: 'sm' }) : null, opt.label)])
  }
  return el
}

/** Switch (checkbox with role=switch). */
export function toggle({ label, checked, onChange, disabled, id = uid('sw'), describedBy }) {
  const input = h('input', { type: 'checkbox', role: 'switch', id, class: 'switch__input', checked: !!checked, disabled, 'aria-describedby': describedBy || null })
  input.addEventListener('change', () => onChange?.(input.checked, input))
  return { el: h('label', { class: 'switch', for: id }, input, h('span', { class: 'switch__track', 'aria-hidden': 'true' }), h('span', { class: 'switch__label' }, label)), input }
}

/* ───────────────────────── display ───────────────────────── */

/** @param {string} text @param {'neutral'|'success'|'warning'|'danger'|'info'|'brand'} [tone] */
export function badge(text, tone = 'neutral', iconName) {
  return h('span', { class: `badge badge--${tone}` }, iconName ? icon(iconName, { size: 'sm' }) : null, text)
}

/** How the enrolment script installed the tunnel (device.install_scope). */
export function installScope(d, { long = false } = {}) {
  if (d.install_scope === 'system') {
    return h('span', { class: 'install-scope', title: 'Installed with sudo / as Administrator: starts at boot, runs when nobody is logged in.' },
      badge('Permanent', 'success'), long ? h('span', null, 'Whole machine; starts at boot.') : null)
  }
  if (d.install_scope === 'user') {
    const who = d.install_user ? h('span', { class: 'mono' }, d.install_user) : 'one user'
    return h('span', { class: 'install-scope', title: `Installed without admin rights: runs only while ${d.install_user || 'one user'} is logged in.` },
      badge('Temporary', 'warning'), long ? h('span', null, 'Runs only while ', who, ' is logged in.') : who)
  }
  return h('span', { class: 'muted', title: 'Enrolled by an older script that did not report how it installed.' }, 'Not reported')
}

/** Presence: online / offline / pending / disabled — dot + text (never colour alone). */
export function presence(device, { compact = false } = {}) {
  const state = device.status === 'disabled' ? 'disabled' : device.status === 'pending' ? 'pending' : device.online ? 'online' : 'offline'
  const text = { online: 'Online', offline: 'Offline', pending: 'Pending', disabled: 'Disabled' }[state]
  return h('span', { class: `presence presence--${state}`, title: text },
    h('span', { class: 'presence__dot', 'aria-hidden': 'true' }),
    h('span', { class: compact ? 'sr-only' : 'presence__text' }, text))
}

/** Group pill with the group's domain colour. */
export function groupPill(group) {
  if (!group) return h('span', { class: 'muted' }, 'No group')
  const color = ['teal', 'violet', 'amber', 'rose', 'sky', 'lime', 'slate', 'orange'].includes(group.color) ? group.color : 'slate'
  return h('span', { class: `pill pill--group pill--${color}` }, h('span', { class: 'pill__swatch', 'aria-hidden': 'true' }), group.name)
}

/** Service chip (ssh/rdp/vnc) — highlighted when forwarded. */
export function serviceChip(svc) {
  return h('span', { class: ['chip', svc.forwarded && 'chip--live'], title: svc.forwarded ? `${serviceLabel(svc.kind)} is being forwarded` : `${serviceLabel(svc.kind)} is not forwarded right now` },
    icon(`domain.service.${svc.kind}`, { size: 'sm' }), serviceLabel(svc.kind))
}

/** OS icon with label for screen readers. */
export function osIcon(os, { withText = false } = {}) {
  const key = ['linux', 'macos', 'windows'].includes(os) ? os : 'unknown'
  return h('span', { class: 'os' }, icon(`domain.os.${key}`, { size: 'sm', label: withText ? undefined : osLabel(os) }), withText ? osLabel(os) : null)
}

/** Relative time with absolute tooltip; kept fresh by a shared 30 s ticker. */
export function relTime(iso, { never = 'Never' } = {}) {
  if (!iso) return h('span', { class: 'muted' }, never)
  const t = h('time', { datetime: iso, title: dateTimeTitle(iso), class: 'reltime' }, relativeTime(iso))
  t.dataset.rel = iso
  return t
}
setInterval(() => {
  for (const t of document.querySelectorAll('time[data-rel]')) t.textContent = relativeTime(t.dataset.rel)
}, 30000)

/**
 * A stat / metric card with ⓘ help (HELP-2).
 * @param {{label:string, value:string|number|Node, sub?:string|Node, icon?:string, tone?:string, href?:string, helpScreen?:string, helpKey?:string}} o
 */
export function statCard(o) {
  const tip = o.helpScreen ? columnHelp(o.helpScreen, o.helpKey) : ''
  const inner = [
    h('div', { class: 'stat__top' },
      o.icon ? h('span', { class: `stat__icon stat__icon--${o.tone || 'brand'}` }, icon(o.icon)) : null,
      h('span', { class: 'stat__label' }, o.label),
      tip ? infoTip(tip, o.label) : null),
    h('div', { class: 'stat__value' }, o.value),
    o.sub ? h('div', { class: 'stat__sub' }, o.sub) : null,
  ]
  return o.href ? h('a', { class: `stat stat--link stat--${o.tone || 'brand'}`, href: o.href }, inner) : h('div', { class: `stat stat--${o.tone || 'brand'}` }, inner)
}

/** ⓘ popover: a button revealing help text (keyboard and touch friendly). */
export function infoTip(text, about) {
  const id = uid('tip')
  const tip = h('span', { class: 'tip__bubble', role: 'tooltip', id, hidden: true }, text)
  const btn = h('button', { type: 'button', class: 'tip__btn', 'aria-label': `About ${about}`, 'aria-describedby': id, 'aria-expanded': 'false' }, icon('status.info', { size: 'sm' }))
  const wrap = h('span', { class: 'tip' }, btn, tip)
  const show = (on) => { tip.hidden = !on; btn.setAttribute('aria-expanded', String(on)) }
  btn.addEventListener('click', (ev) => { ev.stopPropagation(); show(tip.hidden) })
  btn.addEventListener('mouseenter', () => show(true))
  wrap.addEventListener('mouseleave', () => show(false))
  btn.addEventListener('blur', () => show(false))
  btn.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') show(false) })
  return wrap
}

/** Key/value fact list. @param {Array<[string, any, string?]>} rows [label, value, helpText?] */
export function kv(rows) {
  return h('dl', { class: 'kv' }, rows.filter(Boolean).map(([k, v, tipText]) => h('div', { class: 'kv__row' },
    h('dt', null, k, tipText ? infoTip(tipText, k) : null),
    h('dd', null, v === undefined || v === null || v === '' ? h('span', { class: 'muted' }, '—') : v))))
}

/** Monospace block with a copy button. */
export function codeBlock(text, { label = 'Copy', wrap = false } = {}) {
  // A long command scrolls sideways: the <pre> takes focus so keyboard users can scroll it with the
  // arrow keys (WCAG 2.1.1; axe scrollable-region-focusable). The global :focus-visible ring shows it.
  return h('div', { class: ['code', wrap && 'code--wrap'] },
    h('pre', { tabindex: '0', 'aria-label': 'Command text' }, h('code', null, text)),
    copyButton(text, { label, compact: true, variant: 'ghost' }))
}

/* ───────────────────────── states ───────────────────────── */

/** Loading skeleton. @param {'rows'|'cards'|'detail'|'text'} kind */
export function skeleton(kind = 'rows', n = 6) {
  const el = h('div', { class: `skeleton-wrap skeleton-wrap--${kind}`, 'aria-busy': 'true', role: 'status' }, h('span', { class: 'sr-only' }, 'Loading…'))
  for (let i = 0; i < n; i++) el.append(h('div', { class: `skeleton skeleton--${kind === 'cards' ? 'card' : kind === 'detail' ? 'block' : 'row'}` }))
  return el
}

/**
 * The RemoteHound mascot (docs/BRAND.md). Decorative: the artwork is a CSS background served from
 * /ui/brand/ (light/dark file picked by the theme), so no inline SVG and nothing for screen readers.
 * @param {'idle'|'waiting'|'lost'} [state] waiting = slow head tilt (stops under reduced motion); lost = tilted
 */
export function mascot(state = 'idle') {
  return h('span', { class: ['mascot', state !== 'idle' && `mascot--${state}`], 'aria-hidden': 'true' })
}

/**
 * Empty state with guidance from the registry (HELP-4). A registry entry with `"mascot": "waiting"`
 * (or o.mascot) shows the hound instead of an icon — used for "nothing yet, start here" moments.
 * @param {string} key registry `empty` key
 * @param {{action?:Node, title?:string, body?:string, icon?:string, mascot?:'idle'|'waiting'|'lost'}} [o]
 */
export function emptyState(key, o = {}) {
  const e = emptyHelp(key) || {}
  let action = o.action || null
  if (!action && e.action && (!e.action.permission || can(e.action.permission))) {
    action = linkButton({ href: e.action.href, label: e.action.label, variant: 'primary', icon: e.action.icon || 'action.add' })
  }
  const pose = o.mascot || e.mascot
  return h('div', { class: 'state state--empty' },
    pose
      ? h('div', { class: 'state__art state__art--mascot', 'aria-hidden': 'true' }, mascot(pose))
      : h('div', { class: 'state__art', 'aria-hidden': 'true' }, icon(o.icon || e.icon || 'domain.brand', { size: 'xl' })),
    h('h2', { class: 'state__title' }, o.title || e.title || 'Nothing here yet'),
    (o.body || e.body) ? h('p', { class: 'state__body' }, o.body || e.body) : null,
    action ? h('div', { class: 'state__actions' }, action) : null)
}

/** Human message + fix for an ApiError (HELP-3). */
export function describeError(err) {
  const help = errorHelp(err?.code || 'INTERNAL') || {}
  return {
    title: help.title || err?.title || 'Something went wrong',
    detail: err?.detail && err.detail !== help.title ? err.detail : '',
    fix: help.fix || '',
    requestId: err?.requestId || '',
    code: err?.code || 'INTERNAL',
    doc: help.doc || '',
  }
}

/**
 * Error state: what happened, how to fix it, request id, retry.
 * @param {any} err ApiError
 * @param {() => void} [onRetry]
 */
export function errorState(err, onRetry) {
  const d = describeError(err)
  return h('div', { class: 'state state--error', role: 'alert' },
    h('div', { class: 'state__art state__art--danger', 'aria-hidden': 'true' }, icon(err?.status === 0 ? 'domain.presence.offline' : 'status.danger', { size: 'xl' })),
    h('h2', { class: 'state__title' }, d.title),
    d.detail ? h('p', { class: 'state__body' }, d.detail) : null,
    d.fix ? h('p', { class: 'state__fix' }, d.fix) : null,
    h('p', { class: 'state__meta' }, h('span', null, 'Code ', h('code', null, d.code)),
      d.requestId ? h('span', null, ' · Request ID ', h('code', null, d.requestId), ' ', copyButton(d.requestId, { label: 'Copy request ID', compact: true, variant: 'ghost' })) : null),
    h('div', { class: 'state__actions' },
      onRetry ? button({ label: 'Try again', icon: 'action.refresh', variant: 'primary', onClick: onRetry }) : null,
      d.doc ? button({ label: 'Read the guide', variant: 'ghost', icon: 'object.document', onClick: () => openDoc(d.doc) }) : null))
}

/** Toast for a failed action, using registry fix text. */
export function toastError(err, fallback = 'That did not work') {
  const d = describeError(err)
  return toast(d.title || fallback, { tone: 'danger', detail: [d.detail, d.fix].filter(Boolean).join(' '), requestId: d.requestId })
}

/**
 * Generic four-state loader for a region.
 * @param {HTMLElement} container
 * @param {{load:() => Promise<any>, render:(data:any) => Node, isEmpty?:(data:any)=>boolean, emptyKey?:string, skeleton?:string}} o
 * @returns {Promise<void>} resolves after the region is rendered (never rejects)
 */
export async function load(container, o) {
  replace(container, skeleton(o.skeleton || 'detail', o.skeleton === 'cards' ? 4 : 3))
  try {
    const data = await o.load()
    if (o.isEmpty?.(data)) replace(container, emptyState(o.emptyKey))
    else replace(container, o.render(data))
  } catch (err) {
    if (err?.name === 'AbortError') return
    log.warn('load.failed', { code: err?.code, status: err?.status })
    replace(container, errorState(err, () => load(container, o)))
  }
}

/* ───────────────────────── forms ───────────────────────── */

/**
 * A labelled form field with helper text from the registry and error display.
 * @param {{id:string, label:string, help?:string|false, type?:'text'|'number'|'email'|'password'|'textarea'|'select'|'multiselect'|'checkbox'|'url',
 *          value?:any, options?:Array<{value:string,label:string}>, required?:boolean, min?:number, max?:number, maxlength?:number,
 *          placeholder?:string, autocomplete?:string, disabled?:boolean, mono?:boolean, suffix?:string, onInput?:Function, rows?:number}} spec
 *   id: the help key, "screen.field" (e.g. "devices.name"); the DOM id is derived from it.
 *   help: override text, or false when the field is self-explanatory.
 */
export function field(spec) {
  const domId = `f-${spec.id.replace(/[^\w-]/g, '-')}`
  const helpText = spec.help === false ? '' : (spec.help || fieldHelp(spec.id))
  const helpId = helpText ? `${domId}-help` : null
  const errId = `${domId}-err`
  const describedBy = [helpId, errId].filter(Boolean).join(' ')
  const common = { id: domId, name: spec.id.split('.').pop(), 'aria-describedby': describedBy, disabled: spec.disabled, required: spec.required }
  let input
  const t = spec.type || 'text'
  if (t === 'textarea') {
    input = h('textarea', { ...common, class: ['input', 'input--area', spec.mono && 'input--mono'], rows: spec.rows || 3, maxlength: spec.maxlength, placeholder: spec.placeholder })
    input.value = spec.value ?? ''
  } else if (t === 'select' || t === 'multiselect') {
    input = h('select', { ...common, class: 'input input--select', multiple: t === 'multiselect' },
      (spec.options || []).map(op => h('option', { value: op.value }, op.label)))
    setValue(spec.value)
  } else if (t === 'checkbox') {
    input = h('input', { ...common, type: 'checkbox', role: 'switch', class: 'switch__input', checked: !!spec.value })
  } else {
    input = h('input', { ...common, type: t, class: ['input', spec.mono && 'input--mono'], min: spec.min, max: spec.max, maxlength: spec.maxlength,
      placeholder: spec.placeholder, autocomplete: spec.autocomplete || (t === 'password' ? 'new-password' : 'off'), spellcheck: spec.mono ? 'false' : null,
      inputmode: t === 'number' ? 'numeric' : null })
    input.value = spec.value ?? ''
  }
  if (spec.onInput) input.addEventListener(t === 'select' || t === 'checkbox' || t === 'multiselect' ? 'change' : 'input', spec.onInput)
  const err = h('p', { id: errId, class: 'field__error', 'aria-live': 'polite' })
  const label = h('label', { for: domId, class: 'field__label' }, spec.label, spec.required ? h('span', { class: 'field__req', 'aria-hidden': 'true' }, ' *') : null)
  let control = input
  if (t === 'checkbox') {
    control = h('label', { class: 'switch', for: domId }, input, h('span', { class: 'switch__track', 'aria-hidden': 'true' }), h('span', { class: 'switch__label' }, spec.label))
  } else if (spec.suffix) {
    control = h('div', { class: 'input-group' }, input, h('span', { class: 'input-group__suffix' }, spec.suffix))
  }
  const el = h('div', { class: ['field', t === 'checkbox' && 'field--switch'] },
    t === 'checkbox' ? null : label,
    control,
    helpText ? h('p', { id: helpId, class: 'field__help' }, helpText) : null,
    err)
  el.dataset.helpKey = spec.id

  function setValue(v) {
    if (t === 'checkbox') { input.checked = !!v; return }
    if (t === 'multiselect') { const set = new Set(v || []); for (const o of input.options) o.selected = set.has(o.value); return }
    input.value = v ?? ''
  }
  function getValue() {
    if (t === 'checkbox') return input.checked
    if (t === 'multiselect') return [...input.selectedOptions].map(o => o.value)
    if (t === 'number') return input.value === '' ? null : Number(input.value)
    return input.value
  }
  function setError(msg) {
    err.textContent = msg || ''
    el.classList.toggle('field--invalid', !!msg)
    input.setAttribute('aria-invalid', msg ? 'true' : 'false')
  }
  return { el, input, get: getValue, set: setValue, setError, key: spec.id.split('.').pop() }
}

/**
 * Multi-picker as a checkbox list (touch-friendly alternative to <select multiple>), bound to real data.
 * @param {{id:string, label:string, options:Array<{value:string,label:string|Node}>, value?:string[], disabled?:boolean, emptyText?:string}} spec
 */
export function checkList(spec) {
  const helpText = fieldHelp(spec.id)
  const helpId = uid('cl-help')
  const errId = uid('cl-err')
  const err = h('p', { id: errId, class: 'field__error', 'aria-live': 'polite' })
  const list = h('div', { class: 'checklist-input' })
  const el = h('fieldset', { class: 'field', 'aria-describedby': `${helpText ? helpId : ''} ${errId}`.trim() },
    h('legend', { class: 'field__label' }, spec.label), list,
    helpText ? h('p', { id: helpId, class: 'field__help' }, helpText) : null, err)
  let selected = new Set(spec.value || [])
  function setOptions(options) {
    replace(list, options.length ? options.map(op => {
      const id = uid('cl')
      const input = h('input', { type: 'checkbox', id, value: op.value, checked: selected.has(op.value), disabled: spec.disabled, class: 'check__input' })
      input.addEventListener('change', () => { if (input.checked) selected.add(op.value); else selected.delete(op.value) })
      return h('label', { class: 'check', for: id }, input, h('span', { class: 'check__box', 'aria-hidden': 'true' }, icon('state.check', { size: 'sm' })), h('span', null, op.label))
    }) : h('p', { class: 'muted' }, spec.emptyText || 'Nothing to choose from yet.'))
  }
  setOptions(spec.options || [])
  return {
    el, setOptions,
    get: () => [...selected],
    set: (v) => { selected = new Set(v || []); for (const i of list.querySelectorAll('input')) i.checked = selected.has(i.value) },
    setError: (msg) => { err.textContent = msg || ''; el.classList.toggle('field--invalid', !!msg) },
    input: el, key: spec.id.split('.').pop(),
  }
}

/**
 * Show server field errors (problem+json `errors[]`) next to the right inputs; focus the first.
 * @param {Record<string, ReturnType<typeof field>>} fields keyed by API field name
 * @param {any} err ApiError
 * @returns {boolean} true if at least one field error was shown
 */
export function applyFieldErrors(fields, err) {
  for (const f of Object.values(fields)) f.setError('')
  let first = null
  for (const [k, msg] of Object.entries(err?.fieldErrors || {})) {
    const f = fields[k] || fields[k.split('.')[0]]
    if (f) { f.setError(msg); first = first || f }
  }
  first?.input.focus()
  return !!first
}

/** Inline form-level error banner. */
export function formError(err) {
  const d = describeError(err)
  return h('div', { class: 'banner banner--danger', role: 'alert' }, icon('status.danger'),
    h('div', null, h('strong', null, d.title), d.detail ? h('p', null, d.detail) : null, d.fix ? h('p', null, d.fix) : null,
      d.requestId ? h('p', { class: 'muted' }, 'Request ID ', h('code', null, d.requestId)) : null))
}

/** Generic banner. @param {'info'|'warning'|'danger'|'success'} tone */
export function banner(tone, title, body, action) {
  const ic = { info: 'status.info', warning: 'status.warning', danger: 'status.danger', success: 'status.success' }[tone]
  return h('div', { class: `banner banner--${tone}`, role: tone === 'danger' ? 'alert' : 'status' }, icon(ic),
    h('div', { class: 'banner__text' }, h('strong', null, title), body ? h('p', null, body) : null), action || null)
}

/* ───────────────────────── data grid ───────────────────────── */

/**
 * The shared data grid.
 * @param {{
 *   columns: Array<{id:string, label:string, value?:(row:any)=>any, render?:(row:any)=>any, sortable?:boolean,
 *                   help?:boolean, className?:string, primary?:boolean, exportable?:boolean, align?:'end'}>,
 *   helpScreen: string,                       registry screen whose `columns` hold ⓘ text
 *   load?: (q:{pageToken:string, query:object, signal:AbortSignal}) => Promise<{data:any[], meta:any}>,
 *   rows?: any[],                             static rows instead of load
 *   query?: object,                           server-side filters passed to load
 *   rowHref?: (row:any) => string|null,       drill-down target
 *   onRowClick?: (row:any) => void,
 *   emptyKey: string,                         registry empty-state key
 *   exportName?: string,                      file base name; omit to hide export
 *   initialSort?: {id:string, dir:'asc'|'desc'},
 *   searchable?: boolean, searchPlaceholder?: string,
 *   toolbar?: Node,                           extra filter controls (server-side)
 *   rowKey?: (row:any) => string,
 *   expand?: (row:any) => Node,               optional expandable detail row
 *   label: string                             accessible table name
 * }} o
 */
export function grid(o) {
  let rows = []
  let nextToken = ''
  let pages = 0
  let sort = o.initialSort || null
  let filterText = ''
  let query = { ...(o.query || {}) }
  let ctrl = null
  let state = 'loading'
  let lastError = null
  const expanded = new Set()
  const key = o.rowKey || ((r) => r.id)
  const val = (c, r) => (c.value ? c.value(r) : r[c.id])

  const search = o.searchable === false ? null : h('input', {
    type: 'search', class: 'input input--search', placeholder: o.searchPlaceholder || 'Filter loaded rows',
    'aria-label': `Filter ${o.label}`,
    onInput: () => { filterText = search.value.trim().toLowerCase(); paint() },
  })
  const count = h('span', { class: 'grid__count', 'aria-live': 'polite' })
  const exportBtns = o.exportName ? h('div', { class: 'grid__export' },
    button({ label: 'CSV', icon: 'action.export', variant: 'ghost', size: 'sm', title: 'Export the rows shown as CSV', onClick: () => exportRows('csv') }),
    button({ label: 'JSON', icon: 'action.export', variant: 'ghost', size: 'sm', title: 'Export the rows shown as JSON', onClick: () => exportRows('json') })) : null
  const toolbar = h('div', { class: 'grid__toolbar' },
    search ? h('div', { class: 'grid__search' }, icon('action.search', { size: 'sm' }), search) : null,
    o.toolbar || null,
    h('div', { class: 'grid__meta' }, count, exportBtns))
  const region = h('div', { class: 'grid__region' })
  const more = h('div', { class: 'grid__more' })
  const el = h('div', { class: 'grid' }, toolbar, region, more)

  function visible() {
    let out = rows
    if (filterText) {
      out = out.filter(r => o.columns.some(c => String(val(c, r) ?? '').toLowerCase().includes(filterText)))
    }
    if (sort) {
      const c = o.columns.find(x => x.id === sort.id)
      if (c) {
        const dir = sort.dir === 'desc' ? -1 : 1
        out = [...out].sort((a, b) => {
          const x = val(c, a), y = val(c, b)
          if (x === y) return 0
          if (x === null || x === undefined || x === '') return 1
          if (y === null || y === undefined || y === '') return -1
          return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) * dir
        })
      }
    }
    return out
  }

  function headerCell(c) {
    const tipText = c.help === false ? '' : columnHelp(o.helpScreen, c.id)
    const sortable = c.sortable !== false
    const ariaSort = sort?.id === c.id ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'
    const label = sortable
      ? h('button', { type: 'button', class: 'grid__sort', onClick: () => {
        sort = sort?.id === c.id ? { id: c.id, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { id: c.id, dir: 'asc' }
        paint()
      } }, c.label, icon(sort?.id === c.id ? (sort.dir === 'asc' ? 'state.collapse' : 'state.expand') : 'action.sort', { size: 'sm', className: 'grid__sorticon' }))
      : h('span', null, c.label)
    return h('th', { scope: 'col', class: [c.align === 'end' && 'is-end'], 'aria-sort': sortable ? ariaSort : null }, h('span', { class: 'grid__th' }, label, tipText ? infoTip(tipText, c.label) : null))
  }

  function bodyRow(r) {
    const href = o.rowHref?.(r) || null
    const tr = h('tr', { class: ['grid__row', (href || o.onRowClick) && 'is-clickable', o.expand && expanded.has(key(r)) && 'is-expanded'] })
    o.columns.forEach((c, i) => {
      let content = c.render ? c.render(r) : val(c, r)
      if (content === undefined || content === null || content === '') content = h('span', { class: 'muted' }, '—')
      if (href && (c.primary || (i === 0 && !o.columns.some(x => x.primary)))) content = h('a', { href, class: 'grid__link' }, content)
      tr.append(h('td', { class: [c.className, c.primary && 'is-primary', c.align === 'end' && 'is-end'], 'data-label': c.label }, content))
    })
    if (o.expand) {
      const open = expanded.has(key(r))
      tr.append(h('td', { class: 'grid__expandcell', 'data-label': '' }, iconButton({
        icon: open ? 'state.collapse' : 'state.expand', label: open ? 'Hide details' : 'Show details', size: 'sm', pressed: open,
        onClick: (ev) => { ev.stopPropagation(); open ? expanded.delete(key(r)) : expanded.add(key(r)); paint() },
      })))
    }
    if (href || o.onRowClick) {
      tr.addEventListener('click', (ev) => {
        if (ev.target.closest('a,button,input,select,label,textarea')) return
        if (globalThis.getSelection?.().toString()) return
        if (o.onRowClick) o.onRowClick(r)
        else tr.querySelector('a.grid__link')?.click()
      })
    }
    const out = [tr]
    if (o.expand && expanded.has(key(r))) {
      out.push(h('tr', { class: 'grid__detail' }, h('td', { colspan: String(o.columns.length + 1) }, o.expand(r))))
    }
    return out
  }

  function paint() {
    if (state === 'loading') { replace(region, skeleton('rows', 6)); count.textContent = ''; replace(more); return }
    if (state === 'error') { replace(region, errorState(lastError, () => reload())); count.textContent = ''; replace(more); return }
    if (!rows.length) {
      const filtered = Object.values(query).some(v => v !== '' && v !== undefined && v !== null)
      replace(region, filtered
        ? emptyState('filtered', { action: button({ label: 'Clear filters', icon: 'domain.action.clear', variant: 'secondary', onClick: () => o.onClearFilters?.() }) })
        : emptyState(o.emptyKey))
      count.textContent = ''
      replace(more)
      return
    }
    const vis = visible()
    count.textContent = filterText ? `${vis.length} of ${rows.length} shown` : `${rows.length}${nextToken ? '+' : ''} ${rows.length === 1 ? 'row' : 'rows'}`
    const table = h('table', { class: 'grid__table' },
      h('caption', { class: 'sr-only' }, o.label),
      h('thead', null, h('tr', null, o.columns.map(headerCell), o.expand ? h('th', { scope: 'col', class: 'grid__expandcell' }, h('span', { class: 'sr-only' }, 'Details')) : null)),
      h('tbody', null, vis.map(bodyRow)))
    replace(region, vis.length ? h('div', { class: 'grid__scroll', tabindex: '0', role: 'region', 'aria-label': o.label }, table)
      : h('p', { class: 'grid__nomatch' }, 'No loaded rows match that filter.'))
    replace(more, nextToken ? button({ label: 'Load more', icon: 'state.expand', variant: 'secondary', onClick: () => fetchPage(true) }) : null)
  }

  async function fetchPage(append = false) {
    if (o.rows) { rows = o.rows; state = 'data'; paint(); return }
    ctrl?.abort()
    ctrl = new AbortController()
    try {
      const r = await o.load({ pageToken: append ? nextToken : '', query, signal: ctrl.signal })
      rows = append ? rows.concat(r.data || []) : (r.data || [])
      pages = append ? pages + 1 : 1
      nextToken = r.meta?.next_page_token || ''
      state = 'data'
    } catch (err) {
      if (err?.name === 'AbortError') return
      if (append) { toastError(err, 'Could not load more rows'); return }
      lastError = err
      state = 'error'
    }
    paint()
  }

  /** Re-query from the first page (new server-side filters). */
  function reload(newQuery) {
    if (newQuery) query = { ...newQuery }
    state = 'loading'
    expanded.clear()
    paint()
    return fetchPage(false)
  }

  /** Silent refresh: keeps rows on screen until new data arrives (live views). Skipped once the
   *  user has paged with "Load more", so their extra rows are not thrown away. */
  function refresh() { return pages > 1 ? Promise.resolve() : fetchPage(false) }

  /** Replace the rows directly (streams, client-side sources). */
  function setRows(next) {
    rows = next
    nextToken = ''
    state = 'data'
    paint()
  }

  /** Show an error state for an externally managed source. */
  function setError(err) {
    lastError = err
    state = 'error'
    paint()
  }

  function exportRows(fmt) {
    const vis = visible()
    const cols = o.columns.filter(c => c.exportable !== false)
    let blob
    if (fmt === 'json') blob = new Blob([JSON.stringify(vis, null, 2)], { type: 'application/json' })
    else {
      const lines = [cols.map(c => csvCell(c.label)).join(',')]
      for (const r of vis) lines.push(cols.map(c => csvCell(val(c, r))).join(','))
      blob = new Blob([lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' })
    }
    saveBlob(blob, `${o.exportName}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${fmt}`)
    log.info('grid.export', { screen: o.helpScreen, format: fmt, rows: vis.length })
  }

  paint()
  fetchPage(false)
  return { el, reload, refresh, setRows, setError, rows: () => rows, setQuery: (q) => { query = { ...q } } }
}

/** Trigger a download of an in-memory Blob. */
export function saveBlob(blob, name) {
  const href = URL.createObjectURL(blob)
  const a = h('a', { href, download: name, class: 'sr-only' })
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(href), 10000)
}

/**
 * A labelled filter <select> for grid toolbars.
 * @param {{label:string, value?:string, options:Array<{value:string,label:string}>, onChange:(v:string)=>void, allLabel?:string}} o
 */
export function filterSelect(o) {
  const id = uid('flt')
  const sel = h('select', { id, class: 'input input--select input--sm' },
    h('option', { value: '' }, o.allLabel || 'All'),
    o.options.map(op => h('option', { value: op.value }, op.label)))
  sel.value = o.value || ''
  sel.addEventListener('change', () => o.onChange(sel.value))
  return h('div', { class: 'filter' }, h('label', { for: id, class: 'filter__label' }, o.label), sel)
}

/** Dispatches rh:unmount to every element that registered cleanup, then clears the node. */
export function unmount(root) {
  for (const n of root.querySelectorAll('.tabs, [data-cleanup]')) n.dispatchEvent(new Event('rh:unmount'))
}
