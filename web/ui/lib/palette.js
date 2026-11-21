/**
 * Command palette (HELP-8): Ctrl/Cmd+K from anywhere.
 *
 * Contract
 *  - `initPalette({nav, navigate})` binds the shortcut. `nav` is the list of screens the user may see
 *    ({path, label, icon}). Results: screens, devices (live search via api.js when the user has
 *    device.read) and help entries (help.searchHelp). Arrow keys move, Enter runs, Esc closes.
 *  - Implements the WAI-ARIA combobox + listbox pattern inside a modal <dialog>.
 */
import { h, replace, uid } from './dom.js'
import { icon } from './icons.js'
import { api } from './api.js'
import { can } from './session.js'
import { searchHelp, openHelp, screenHelp } from './help.js'
import { log } from './log.js'

let opts = null
let dialog = null

export function initPalette(o) {
  opts = o
  document.addEventListener('keydown', (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault()
      openPalette()
    }
  })
}

export function openPalette() {
  if (dialog) { dialog.querySelector('input').focus(); return }
  const listId = uid('pal-list')
  const input = h('input', {
    type: 'text', class: 'palette__input', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': listId,
    'aria-autocomplete': 'list', placeholder: 'Jump to a screen, find a device, or search help…', autocomplete: 'off', spellcheck: 'false',
    'aria-label': 'Command palette',
  })
  const list = h('ul', { id: listId, class: 'palette__list', role: 'listbox', 'aria-label': 'Results' })
  dialog = h('dialog', { class: 'palette', 'aria-label': 'Command palette' },
    h('div', { class: 'palette__box' },
      h('div', { class: 'palette__head' }, icon('action.search'), input, h('kbd', { class: 'kbd' }, 'Esc')),
      list,
      h('p', { class: 'palette__foot' }, h('kbd', { class: 'kbd' }, '↑'), h('kbd', { class: 'kbd' }, '↓'), ' to move · ', h('kbd', { class: 'kbd' }, 'Enter'), ' to open · ', h('kbd', { class: 'kbd' }, '?'), ' help for this screen')))
  let items = []
  let active = 0
  let seq = 0
  let timer = null

  const close = () => { dialog?.close() }
  dialog.addEventListener('close', () => { dialog.remove(); dialog = null })
  dialog.addEventListener('click', (ev) => { if (ev.target === dialog) close() })

  function paint() {
    replace(list, items.length ? items.map((it, i) => {
      const li = h('li', { id: `${listId}-${i}`, role: 'option', class: ['palette__item', i === active && 'is-active'], 'aria-selected': String(i === active) },
        h('span', { class: 'palette__icon' }, icon(it.icon)),
        h('span', { class: 'palette__text' }, h('span', { class: 'palette__title' }, it.title), it.sub ? h('span', { class: 'palette__sub' }, it.sub) : null),
        h('span', { class: 'palette__kind' }, it.kind))
      li.addEventListener('click', () => run(it))
      li.addEventListener('mousemove', () => { if (active !== i) { active = i; paint() } })
      return li
    }) : h('li', { class: 'palette__empty', role: 'presentation' }, 'No matches. Try a device name, a screen, or an error code.'))
    input.setAttribute('aria-activedescendant', items.length ? `${listId}-${active}` : '')
    list.querySelector('.is-active')?.scrollIntoView({ block: 'nearest' })
  }

  function run(it) {
    close()
    log.info('palette.run', { kind: it.kind })
    it.run()
  }

  async function update() {
    const q = input.value.trim().toLowerCase()
    const mine = ++seq
    const navItems = opts.nav.filter(n => !q || n.label.toLowerCase().includes(q) || n.path.includes(q))
      .map(n => ({ kind: 'Screen', icon: n.icon, title: n.label, sub: screenHelp(n.help)?.purpose?.split('. ')[0] || '', run: () => opts.navigate(n.path) }))
    const helpItems = q.length > 1 ? searchHelp(q).map(r => ({
      kind: 'Help', icon: r.kind === 'error' ? 'status.warning' : 'nav.help', title: r.title, sub: r.snippet,
      run: () => openHelp(r.kind === 'screen' ? r.key : r.kind === 'field' ? r.key.split('.')[0] : 'overview', r.kind === 'field' ? { anchor: r.key.split('.').slice(1).join('.') } : {}),
    })) : []
    items = [...navItems.slice(0, q ? 6 : 12), ...helpItems.slice(0, 6)]
    active = 0
    paint()
    if (q.length > 1 && can('device.read')) {
      try {
        const r = await api.get('/api/v1/devices', { q, page_size: 6 })
        if (mine !== seq) return
        const devs = (r.data || []).map(d => ({ kind: 'Device', icon: 'domain.nav.devices', title: d.name, sub: [d.hostname, d.online ? 'online' : 'offline'].filter(Boolean).join(' · '), run: () => opts.navigate(`/devices/${encodeURIComponent(d.id)}`) }))
        items = [...navItems.slice(0, 4), ...devs, ...helpItems.slice(0, 6)]
        paint()
      } catch (e) {
        log.debug('palette.device_search_failed', { code: e?.code })
      }
    }
  }

  input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 120) })
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'ArrowDown') { ev.preventDefault(); active = Math.min(items.length - 1, active + 1); paint() }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); active = Math.max(0, active - 1); paint() }
    else if (ev.key === 'Enter' && items[active]) { ev.preventDefault(); run(items[active]) }
  })
  document.body.append(dialog)
  dialog.showModal()
  input.focus()
  update()
}
