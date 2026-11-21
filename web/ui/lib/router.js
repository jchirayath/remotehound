/**
 * History-API router.
 *
 * Contract
 *  - `match(routes, path)` is pure: routes are `{path:'/devices/:id', …}`; returns
 *    `{route, params}` for the first match (params URL-decoded) or null. Trailing slashes are ignored.
 *  - `createRouter({routes, onRoute})` wires history: `navigate(path, {replace})`, back/forward,
 *    and intercepts clicks on same-origin <a> elements whose path is an app route (not /api, /auth,
 *    /docs, /guacamole, /ui, /e). Modified clicks (ctrl/cmd/shift/middle) and target=_blank are left
 *    to the browser.
 *  - `onRoute({route, params, query, path})` is called for every navigation, including the first.
 */

/** Paths the SPA must never swallow — they are served by the Go server. */
export const SERVER_PREFIXES = ['/api/', '/auth/', '/docs/', '/guacamole', '/ui/', '/e/', '/healthz', '/readyz']

/** @param {string} pattern e.g. '/devices/:id' */
export function compile(pattern) {
  const keys = []
  const src = pattern.replace(/\/+$/, '').split('/').map(seg => {
    if (seg.startsWith(':')) { keys.push(seg.slice(1)); return '([^/]+)' }
    return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }).join('/')
  return { re: new RegExp(`^${src || ''}/?$`), keys }
}

const cache = new Map()

/**
 * @template R
 * @param {Array<R & {path:string}>} routes
 * @param {string} path
 * @returns {{route: R, params: Record<string,string>} | null}
 */
export function match(routes, path) {
  const clean = (path.split(/[?#]/)[0] || '/').replace(/\/{2,}/g, '/')
  for (const route of routes) {
    let c = cache.get(route.path)
    if (!c) { c = compile(route.path); cache.set(route.path, c) }
    const m = c.re.exec(clean === '' ? '/' : clean)
    if (!m) continue
    const params = {}
    c.keys.forEach((k, i) => {
      try { params[k] = decodeURIComponent(m[i + 1]) } catch { params[k] = m[i + 1] }
    })
    return { route, params }
  }
  return null
}

/** Whether a same-origin path belongs to the SPA. */
export function isAppPath(path) {
  return path.startsWith('/') && !SERVER_PREFIXES.some(p => path === p.replace(/\/$/, '') || path.startsWith(p))
}

/**
 * @param {{routes: Array<{path:string}>, notFound: object, onRoute: Function}} opts
 */
export function createRouter({ routes, notFound, onRoute }) {
  const resolve = () => {
    const { pathname, search } = globalThis.location
    const m = match(routes, pathname)
    onRoute({
      route: m ? m.route : notFound,
      params: m ? m.params : {},
      query: Object.fromEntries(new URLSearchParams(search)),
      path: pathname + search,
    })
  }

  const navigate = (to, { replace = false } = {}) => {
    const cur = globalThis.location.pathname + globalThis.location.search
    // A link to the page already shown re-renders it (no new history entry), so a click is never a no-op.
    if (to !== cur || replace) globalThis.history[replace ? 'replaceState' : 'pushState']({}, '', to)
    resolve()
  }

  /** Update the query string without re-rendering the screen (filters, tabs). */
  const setQuery = (params) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
    const s = qs.toString()
    globalThis.history.replaceState({}, '', globalThis.location.pathname + (s ? `?${s}` : ''))
  }

  globalThis.addEventListener('popstate', resolve)
  globalThis.document.addEventListener('click', (ev) => {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return
    const a = ev.target.closest?.('a[href]')
    if (!a || a.target === '_blank' || a.hasAttribute('download')) return
    const url = new URL(a.href, globalThis.location.href)
    if (url.origin !== globalThis.location.origin || !isAppPath(url.pathname)) return
    ev.preventDefault()
    navigate(url.pathname + url.search)
  })

  return { navigate, resolve, setQuery }
}

/**
 * Sanitise a return path (the `rd` query parameter): only same-origin absolute paths are allowed.
 * Rejects protocol-relative ("//evil"), backslash tricks ("/\evil"), schemes and control characters.
 * @param {string|null|undefined} rd
 * @returns {string|null} the path, or null when it is not safe
 */
export function safeReturnPath(rd) {
  const s = String(rd ?? '')
  if (!s.startsWith('/') || s.startsWith('//') || s.includes('\\')) return null
  if (/[\u0000-\u001f\u007f]/.test(s)) return null
  return s
}

/**
 * A session URL returned by POST /devices/{id}/connect or /sessions/{id}/join must be a same-origin
 * relative path (e.g. "/guacamole/?data=…"). Anything else is refused before the UI navigates to it.
 * @param {string} url
 */
export function isSessionUrl(url) {
  return safeReturnPath(url) !== null
}
