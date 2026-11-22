/**
 * RemoteHound web UI — entry point: boot, app shell and routing.
 *
 * Boot: load the help registry and GET /api/v1/me in parallel → 401 redirects to sign-in (api.js),
 * 403 shows the "no access" screen, anything else shows a retryable error. Then the theme is
 * reconciled with the user's stored preference and the router renders the first screen.
 *
 * Screens live in ./screens/<name>.js and are loaded on demand. Each exports
 *   default function render(ctx) → HTMLElement
 * where ctx = {params, query, navigate, setQuery, onCleanup(fn), signal, setTitle(text)}.
 * Cleanups run (and `signal` aborts) when the user leaves the screen, so polling and streams stop.
 *
 * Shell: wide screens get a collapsible sidebar; compact (<600px) a top bar + bottom tab bar
 * (Overview, Devices, Enroll, Sessions, More). Global keys: `?` help, Ctrl/Cmd+K palette.
 */
import { h, replace } from './lib/dom.js'
import { icon } from './lib/icons.js'
import { api, apiEvents, setCsrfToken } from './lib/api.js'
import { session, can, forgetGuacamole } from './lib/session.js'
import { loadHelp, openHelp, setCurrentHelp, screenHelp } from './lib/help.js'
import { initTheme, applyTheme, setTheme, currentTheme, MODES } from './lib/theme.js'
import { createRouter, match } from './lib/router.js'
import { initPalette, openPalette } from './lib/palette.js'
import { drawer, toast, toastError, errorState, segmented, skeleton, unmount } from './lib/ui.js'
import { log } from './lib/log.js'
import { ROUTES, NOT_FOUND, TABBAR } from './lib/routes.js'


const root = document.getElementById('app')
let main, sidebarNav, tabbar, offlineBanner, router
let current = { ctrl: null, cleanups: [], route: null }

const allowed = (r) => !r.perm || can(r.perm)

/* ───────────────────────── boot ───────────────────────── */

async function boot() {
  replace(root, skeleton('detail', 3))
  // Public routes (the sign-in page) render without a session and never call /api/v1/me.
  const pub = match(ROUTES, location.pathname)
  if (pub?.route.public) {
    try { await loadHelp() } catch (e) { log.warn('help.load_failed', { code: e?.code }) }
    root.removeAttribute('aria-busy')
    root.classList.remove('boot')
    applyTheme(document.documentElement.getAttribute('data-theme') || 'system') // fills theme-color without a session
    setDocTitle(pub.route.label)
    return renderStandalone(pub.route.screen, Object.fromEntries(new URLSearchParams(location.search)))
  }
  try {
    const [, me] = await Promise.all([loadHelp(), api.get('/api/v1/me')])
    session.me = me.data
    setCsrfToken(me.data.csrf_token)
    initTheme(me.data.theme)
    root.removeAttribute('aria-busy')
    root.classList.remove('boot')
    buildShell()
    router = createRouter({ routes: ROUTES, notFound: NOT_FOUND, onRoute: show })
    initPalette({ nav: ROUTES.filter(r => (r.section || r.palette) && allowed(r)), navigate: router.navigate })
    bindKeys()
    router.resolve()
  } catch (err) {
    root.removeAttribute('aria-busy')
    root.classList.remove('boot')
    if (err?.status === 401) return // api.js is redirecting to sign-in
    if (err?.status === 403) return renderStandalone('noaccess', { reason: 'forbidden', error: err })
    log.error('boot.failed', { code: err?.code, status: err?.status })
    replace(root, h('main', { class: 'standalone' }, errorState(err, boot)))
  }
}

async function renderStandalone(screen, query) {
  const mod = await import(`./screens/${screen}.js`)
  replace(root, h('main', { id: 'main', class: 'standalone' }, mod.default({ params: {}, query, navigate: (p) => location.assign(p), setQuery() {}, onCleanup() {}, signal: new AbortController().signal, setTitle: setDocTitle })))
}

/* ───────────────────────── shell ───────────────────────── */

function brand() {
  return h('a', { href: '/', class: 'brand', 'aria-label': 'RemoteHound home' },
    h('span', { class: 'brand__mark', 'aria-hidden': 'true' }),
    h('span', { class: 'brand__name' }, 'RemoteHound'))
}

function navLink(r, cls) {
  return h('a', { href: r.path, class: cls, dataset: { path: r.path } }, icon(r.icon), h('span', { class: `${cls}__label` }, r.label))
}

function themeControl() {
  return segmented({
    label: 'Theme',
    value: currentTheme(),
    options: MODES.map(m => ({ value: m, label: m[0].toUpperCase() + m.slice(1), icon: `domain.theme.${m}` })),
    onChange: async (m) => {
      try { await setTheme(m) } catch (err) { toastError(err, 'Theme saved on this device only') }
    },
  })
}

function userCard() {
  const me = session.me
  const name = me.display_name || me.email || 'Signed in'
  const initials = name.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map(s => s[0].toUpperCase()).join('')
  return h('a', { class: 'user', href: '/profile', dataset: { path: '/profile' }, 'aria-label': `Your profile: ${name}, ${me.role}` },
    h('span', { class: 'user__avatar', 'aria-hidden': 'true' }, initials),
    h('span', { class: 'user__text', 'aria-hidden': 'true' }, h('span', { class: 'user__name' }, name), h('span', { class: 'user__role' }, me.role)))
}

async function signOut() {
  let redirect = ''
  try {
    const r = await api.post('/auth/logout')
    redirect = r?.data?.redirect || ''
  } catch (err) {
    log.warn('logout.failed', { code: err?.code })
  }
  forgetGuacamole()
  unmountCurrent()
  // Behind a sign-in proxy the server returns the proxy's sign-out URL: going
  // there ends the proxy's session too (otherwise it signs you straight back in).
  // It comes from server config (RH_PROXY_LOGOUT_URL, validated https or a path).
  if (redirect && (redirect.startsWith('https://') || (redirect.startsWith('/') && !redirect.startsWith('//')))) {
    location.assign(redirect)
    return
  }
  renderStandalone('noaccess', { reason: 'signedout' })
}

function buildShell() {
  const sections = [...new Set(ROUTES.filter(r => r.section).map(r => r.section))]
  sidebarNav = h('nav', { class: 'sidebar__nav', 'aria-label': 'Main' },
    sections.map(s => {
      const items = ROUTES.filter(r => r.section === s && allowed(r))
      if (!items.length) return null
      return h('div', { class: 'navgroup' }, h('p', { class: 'navgroup__title' }, s), h('ul', { class: 'navgroup__list', role: 'list' }, items.map(r => h('li', null, navLink(r, 'navlink')))))
    }))
  const collapse = h('button', { type: 'button', class: 'btn btn--ghost btn--icon sidebar__collapse', 'aria-label': 'Collapse sidebar', 'aria-expanded': 'true',
    onClick: () => {
      const c = document.documentElement.classList.toggle('sidebar-collapsed')
      collapse.setAttribute('aria-expanded', String(!c))
      collapse.setAttribute('aria-label', c ? 'Expand sidebar' : 'Collapse sidebar')
      try { localStorage.setItem('rh.sidebar', c ? 'collapsed' : 'open') } catch (e) { log.debug('sidebar.pref_unavailable', { reason: e?.name }) }
    } }, icon('domain.nav.sidebar'))
  if (document.documentElement.classList.contains('sidebar-collapsed')) { collapse.setAttribute('aria-expanded', 'false'); collapse.setAttribute('aria-label', 'Expand sidebar') }

  const searchBtn = h('button', { type: 'button', class: 'sidebar__search', onClick: openPalette, 'aria-keyshortcuts': 'Control+K Meta+K' },
    icon('action.search', { size: 'sm' }), h('span', { class: 'sidebar__searchlabel' }, 'Search'), h('kbd', { class: 'kbd' }, navigator.platform?.startsWith('Mac') ? '⌘K' : 'Ctrl K'))

  const sidebar = h('aside', { class: 'sidebar' },
    h('div', { class: 'sidebar__top' }, brand(), collapse),
    searchBtn,
    sidebarNav,
    h('div', { class: 'sidebar__foot' },
      themeControl(),
      h('div', { class: 'sidebar__user' }, userCard(),
        h('button', { type: 'button', class: 'btn btn--ghost btn--icon', 'aria-label': 'Sign out', title: 'Sign out', onClick: signOut }, icon('action.logout')))))

  const topbar = h('header', { class: 'topbar' }, brand(),
    h('div', { class: 'topbar__actions' },
      h('button', { type: 'button', class: 'btn btn--ghost btn--icon', 'aria-label': 'Search', onClick: openPalette }, icon('action.search')),
      h('button', { type: 'button', class: 'btn btn--ghost btn--icon', 'aria-label': 'Help for this screen', onClick: () => openHelp() }, icon('nav.help'))))

  tabbar = h('nav', { class: 'tabbar', 'aria-label': 'Main' },
    ROUTES.filter(r => TABBAR.includes(r.path) && allowed(r)).map(r => navLink(r, 'tabbar__item')),
    h('button', { type: 'button', class: 'tabbar__item', onClick: openMore }, icon('action.more'), h('span', { class: 'tabbar__item__label' }, 'More')))

  offlineBanner = h('div', { class: 'offline', role: 'status', hidden: true },
    icon('domain.presence.offline', { size: 'sm' }), h('span', null, 'You are offline or the server is unreachable. Changes will not be saved.'),
    h('button', { type: 'button', class: 'btn btn--sm btn--secondary', onClick: () => router.resolve() }, 'Retry'))
  apiEvents.addEventListener('network', (ev) => { offlineBanner.hidden = ev.detail.online })
  globalThis.addEventListener('offline', () => { offlineBanner.hidden = false })
  globalThis.addEventListener('online', () => { offlineBanner.hidden = true })

  main = h('main', { id: 'main', class: 'main', tabindex: '-1' })
  replace(root, h('div', { class: 'shell' }, sidebar, h('div', { class: 'shell__content' }, topbar, offlineBanner, main), tabbar))
}

function openMore() {
  const items = ROUTES.filter(r => (r.section || r.palette) && !TABBAR.includes(r.path) && allowed(r))
  const panel = drawer({
    title: 'More',
    className: 'drawer--more',
    content: h('div', { class: 'more' },
      h('ul', { class: 'more__list', role: 'list' }, items.map(r => h('li', null, h('a', { href: r.path, class: 'more__link', onClick: () => panel.close() }, icon(r.icon), r.label)))),
      h('div', { class: 'more__section' }, h('p', { class: 'field__label' }, 'Theme'), themeControl()),
      h('div', { class: 'more__section more__user' }, userCard(),
        h('button', { type: 'button', class: 'btn btn--secondary', onClick: () => { panel.close(); signOut() } }, icon('action.logout'), 'Sign out'))),
  })
}

function markActive(route) {
  const target = route.parent || route.path
  for (const a of root.querySelectorAll('a[data-path]')) {
    const on = a.dataset.path === target
    a.classList.toggle('is-active', on)
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current')
  }
  const more = tabbar?.querySelector('button.tabbar__item')
  more?.classList.toggle('is-active', !TABBAR.includes(target) && target !== '*')
}

function setDocTitle(text) { document.title = text ? `${text} · RemoteHound` : 'RemoteHound' }

function unmountCurrent() {
  current.ctrl?.abort()
  for (const fn of current.cleanups.splice(0)) {
    try { fn() } catch (e) { log.warn('screen.cleanup_failed', { message: String(e?.message || e) }) }
  }
  if (main) unmount(main)
}

/* ───────────────────────── routing ───────────────────────── */

async function show({ route, params, query }) {
  unmountCurrent()
  const ctrl = new AbortController()
  current = { ctrl, cleanups: [], route }
  markActive(route)
  setCurrentHelp(route.help)
  setDocTitle(screenHelp(route.help)?.title || route.label)
  replace(main, skeleton('detail', 3))
  let screen = route.screen
  let q = query
  if (!allowed(route)) { screen = 'noaccess'; q = { reason: 'route', permission: route.perm } }
  try {
    const mod = await import(`./screens/${screen}.js`)
    if (ctrl.signal.aborted) return
    const el = mod.default({
      params, query: q, signal: ctrl.signal,
      navigate: router.navigate, setQuery: router.setQuery,
      onCleanup: (fn) => current.cleanups.push(fn),
      setTitle: setDocTitle,
    })
    replace(main, el)
    main.querySelector('.page__title')?.focus({ preventScroll: true })
    main.scrollTop = 0
    globalThis.scrollTo?.(0, 0)
  } catch (err) {
    log.error('screen.load_failed', { screen, message: String(err?.message || err) })
    replace(main, errorState({ code: 'INTERNAL', title: 'This screen failed to load', detail: 'Reload the page; if it keeps happening, check the browser console and the server logs.' }, () => router.resolve()))
  }
}

function bindKeys() {
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== '?' || ev.metaKey || ev.ctrlKey || ev.altKey) return
    const t = ev.target
    if (t.closest?.('input, textarea, select, [contenteditable="true"]') || document.querySelector('dialog[open]')) return
    ev.preventDefault()
    openHelp()
  })
}

globalThis.addEventListener('unhandledrejection', (ev) => {
  const err = ev.reason
  if (err?.name === 'ApiError') { log.warn('unhandled.api_error', { code: err.code }); toast(err.title || 'Request failed', { tone: 'danger', requestId: err.requestId }) }
  else log.error('unhandled.rejection', { message: String(err?.message || err) })
})

boot()
