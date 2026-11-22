/**
 * The data module (CORE-12) — the ONLY file in the UI that touches the network (fetch, EventSource).
 *
 * Contract
 *  - Success bodies are `{data, meta}` (api/openapi.yaml). Every call resolves to
 *    `{data, meta, etag, status, requestId}`; 204 resolves with `data: null`.
 *  - Every failure rejects with ONE type, `ApiError` {status, code, title, detail, requestId,
 *    fieldErrors, retryable}. RFC 9457 problem+json bodies are parsed; anything else (offline,
 *    timeout, HTML error page from a proxy) is mapped to a stable code: NETWORK_OFFLINE, TIMEOUT,
 *    INTERNAL, or HTTP_<status>.
 *  - Headers: credentials 'same-origin' always; on mutations `X-CSRF-Token` (from /api/v1/me or the
 *    `rh_csrf` cookie) and `X-Request-Id`; `Idempotency-Key` on POST; `If-Match` on PATCH when an
 *    etag is passed; PATCH bodies are `application/merge-patch+json`.
 *  - 401 → `config.onUnauthorized(err)` (default: redirect to /auth/login?rd=<current path>; for
 *    PROXY_IDENTITY_MISSING, or after 3 sign-in redirects in 60 s, to /signed-out?reason=proxy).
 *  - Idempotent GETs are retried once on network failure / 502 / 503 / 504 with a short backoff.
 *  - Network state changes are broadcast on `apiEvents` ('network' event, detail {online}) so the
 *    shell can show an offline banner with a retry affordance (UX-8).
 *
 * This module has no DOM dependencies at import time so it can be unit-tested in Node with a
 * stubbed `globalThis.fetch` (tests/api.test.mjs).
 */

export class ApiError extends Error {
  /**
   * @param {{status:number, code:string, title?:string, detail?:string, requestId?:string,
   *          fieldErrors?:Record<string,string>, type?:string}} p
   */
  constructor(p) {
    super(p.detail || p.title || p.code)
    this.name = 'ApiError'
    this.status = p.status
    this.code = p.code
    this.title = p.title || ''
    this.detail = p.detail || ''
    this.requestId = p.requestId || ''
    this.fieldErrors = p.fieldErrors || {}
    this.type = p.type || 'about:blank'
  }

  /** True when trying again later may succeed (offline, timeout, 429, 5xx). */
  get retryable() {
    return this.status === 0 || this.status === 429 || this.status >= 500
  }
}

/** Tunables and hooks; tests and app.js override these. */
export const config = {
  base: '',
  timeoutMs: 20000,
  csrfToken: '',
  onUnauthorized: (err) => {
    const loc = globalThis.location
    if (!loc) return
    // Behind a sign-in proxy, "sign in again" cannot help: the proxy already
    // signed the user in and something dropped the identity. Explain instead
    // of bouncing to /auth/login (which used to loop into a 429).
    if (err?.code === 'PROXY_IDENTITY_MISSING' || tooManySignInRedirects()) {
      loc.assign('/signed-out?reason=proxy')
      return
    }
    const rd = loc.pathname + loc.search
    loc.assign(`/auth/login?rd=${encodeURIComponent(rd)}`)
  },
}

/**
 * Loop brake: true once the browser has been sent to sign-in more than 3 times in 60 s. Whatever
 * the cause (a proxy dropping identity, a cookie the browser refuses), a fourth redirect will not
 * fix it, so the caller shows an explanation instead. Storage may be unavailable (private mode):
 * then the brake is simply off.
 */
export function tooManySignInRedirects(now = Date.now()) {
  try {
    const store = globalThis.sessionStorage
    if (!store) return false
    const recent = JSON.parse(store.getItem('rh.signin_redirects') || '[]').filter(t => now - t < 60_000)
    recent.push(now)
    store.setItem('rh.signin_redirects', JSON.stringify(recent))
    return recent.length > 3
  } catch {
    return false
  }
}

/** Broadcasts `network` events: detail {online: boolean}. */
export const apiEvents = new EventTarget()
let lastOnline = true
function setOnline(online) {
  if (online === lastOnline) return
  lastOnline = online
  apiEvents.dispatchEvent(new CustomEvent('network', { detail: { online } }))
}

/** Remember the CSRF token returned by GET /api/v1/me. */
export function setCsrfToken(token) { config.csrfToken = token || '' }

function csrfToken() {
  if (config.csrfToken) return config.csrfToken
  const cookie = globalThis.document?.cookie || ''
  const m = cookie.match(/(?:^|;\s*)rh_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : ''
}

const newId = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : `${Date.now()}-${performance.now()}`)

/**
 * Build a URL with query parameters; empty/undefined/null values are dropped.
 * @param {string} path
 * @param {Record<string, any>} [query]
 */
export function buildUrl(path, query) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(query || {})) {
    if (v === undefined || v === null || v === '') continue
    qs.append(k, String(v))
  }
  const s = qs.toString()
  return config.base + path + (s ? (path.includes('?') ? '&' : '?') + s : '')
}

/** Convert a JSON pointer ('/services/0/remote_port') to a dotted field key ('services.0.remote_port'). */
export function pointerToKey(pointer) {
  return String(pointer || '').replace(/^#?\//, '').split('/').map(p => p.replace(/~1/g, '/').replace(/~0/g, '~')).join('.')
}

/**
 * Turn a non-2xx Response into an ApiError. Never throws.
 * @param {Response} res
 * @returns {Promise<ApiError>}
 */
export async function parseProblem(res) {
  const headerId = res.headers?.get?.('X-Request-Id') || ''
  const ct = res.headers?.get?.('Content-Type') || ''
  let body = null
  if (/json/i.test(ct)) {
    try { body = await res.json() } catch { body = null }
  }
  if (body && typeof body === 'object' && (body.code || body.title)) {
    const fieldErrors = {}
    for (const e of Array.isArray(body.errors) ? body.errors : []) {
      const key = pointerToKey(e.pointer) || '_'
      fieldErrors[key] = e.detail || e.code || 'invalid'
    }
    return new ApiError({
      status: Number(body.status) || res.status,
      code: String(body.code || `HTTP_${res.status}`),
      title: body.title, detail: body.detail, type: body.type,
      requestId: body.request_id || headerId, fieldErrors,
    })
  }
  return new ApiError({
    status: res.status,
    code: res.status >= 500 ? 'INTERNAL' : `HTTP_${res.status}`,
    title: res.statusText || 'Request failed',
    requestId: headerId,
  })
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms))

/**
 * Core request. Prefer the verb helpers below.
 * @param {string} method
 * @param {string} path  path starting with /api/…
 * @param {{query?:object, body?:any, etag?:string, signal?:AbortSignal, raw?:boolean}} [opts]
 */
export async function request(method, path, opts = {}) {
  const mutation = method !== 'GET' && method !== 'HEAD'
  const headers = { Accept: 'application/json, application/problem+json' }
  if (mutation) {
    headers['X-CSRF-Token'] = csrfToken()
    headers['X-Request-Id'] = newId()
    if (method === 'POST') headers['Idempotency-Key'] = newId()
    if (opts.etag) headers['If-Match'] = opts.etag
  }
  let body
  if (opts.body !== undefined) {
    headers['Content-Type'] = method === 'PATCH' ? 'application/merge-patch+json' : 'application/json'
    body = JSON.stringify(opts.body)
  }
  const url = buildUrl(path, opts.query)
  const attempts = mutation ? 1 : 2
  let lastErr
  for (let i = 0; i < attempts; i++) {
    if (i) await sleep(400 + Math.floor(Math.random() * 400))
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(new Error('timeout')), config.timeoutMs)
    const onAbort = () => ctrl.abort(opts.signal.reason)
    opts.signal?.addEventListener('abort', onAbort, { once: true })
    let res
    try {
      res = await globalThis.fetch(url, { method, headers, body, credentials: 'same-origin', signal: ctrl.signal, cache: 'no-store' })
    } catch (e) {
      clearTimeout(timer)
      if (opts.signal?.aborted) throw e
      const timedOut = ctrl.signal.aborted
      lastErr = new ApiError({
        status: 0, code: timedOut ? 'TIMEOUT' : 'NETWORK_OFFLINE',
        title: timedOut ? 'The server took too long to answer' : 'Cannot reach the server',
        detail: timedOut ? 'The request timed out.' : 'Check your connection; RemoteHound will retry when you ask.',
      })
      if (!timedOut) setOnline(false)
      continue
    } finally {
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
    }
    setOnline(true)
    if (res.status === 401) {
      const err = await parseProblem(res)
      config.onUnauthorized(err)
      throw err
    }
    if (!res.ok) {
      lastErr = await parseProblem(res)
      if (!mutation && [502, 503, 504].includes(res.status)) continue
      // The session's CSRF token changed under us (e.g. an admin change to
      // your own account rotated it). The server refused before doing
      // anything, so fetch the current token and send the request once more.
      if (mutation && lastErr.code === 'AUTH_CSRF_FAILED' && !opts.csrfRetried) {
        const me = await request('GET', '/api/v1/me', { signal: opts.signal })
        if (me?.data?.csrf_token && me.data.csrf_token !== config.csrfToken) {
          setCsrfToken(me.data.csrf_token)
          return request(method, path, { ...opts, csrfRetried: true })
        }
      }
      throw lastErr
    }
    const requestId = res.headers.get('X-Request-Id') || ''
    const etag = res.headers.get('ETag') || ''
    if (opts.raw) return { response: res, status: res.status, requestId, etag }
    if (res.status === 204) return { data: null, meta: {}, status: 204, etag, requestId }
    const ct = res.headers.get('Content-Type') || ''
    if (!/json/i.test(ct)) return { data: await res.text(), meta: {}, status: res.status, etag, requestId }
    const json = await res.json()
    const data = json && typeof json === 'object' && 'data' in json ? json.data : json
    return { data, meta: json?.meta || {}, status: res.status, etag: etag || data?.etag || '', requestId }
  }
  throw lastErr
}

export const api = {
  /** GET → {data, meta, …} */
  get: (path, query, opts = {}) => request('GET', path, { ...opts, query }),
  post: (path, body, opts = {}) => request('POST', path, { ...opts, body }),
  put: (path, body, opts = {}) => request('PUT', path, { ...opts, body }),
  /** JSON Merge Patch with optimistic concurrency: pass the record's etag. */
  patch: (path, body, etag, opts = {}) => request('PATCH', path, { ...opts, body, etag }),
  del: (path, opts = {}) => request('DELETE', path, opts),

  /** Fetch a plain-text resource (e.g. /docs/<page>.md). */
  async text(path) {
    const r = await request('GET', path, { raw: true })
    return r.response.text()
  },

  /**
   * Download a resource as a file (diagnostics bundle, audit CSV) with full error handling.
   * @param {string} path
   * @param {string} filename fallback when the server sends no Content-Disposition
   * @param {object} [query]
   */
  async download(path, filename, query) {
    const r = await request('GET', path, { raw: true, query })
    const blob = await r.response.blob()
    const cd = r.response.headers.get('Content-Disposition') || ''
    const m = cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i)
    const name = m ? decodeURIComponent(m[1]) : filename
    const href = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = href
    a.download = name
    document.body.append(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(href), 10000)
    return name
  },

  /**
   * Open a Server-Sent Events stream. Each `data:` line is parsed as JSON.
   * @param {string} path
   * @param {object} query
   * @param {{onMessage:(obj:any)=>void, onState?:(state:'open'|'error'|'closed')=>void}} handlers
   * @returns {() => void} close function
   */
  stream(path, query, { onMessage, onState }) {
    const es = new EventSource(buildUrl(path, query), { withCredentials: false })
    es.onopen = () => { setOnline(true); onState?.('open') }
    es.onerror = () => onState?.(es.readyState === EventSource.CLOSED ? 'closed' : 'error')
    es.onmessage = (ev) => {
      try { onMessage(JSON.parse(ev.data)) } catch (e) { onState?.('error'); throw e }
    }
    return () => { es.close(); onState?.('closed') }
  },

  /** Absolute same-origin URL for links (recordings, CSV export). */
  url: (path, query) => buildUrl(path, query),
}
