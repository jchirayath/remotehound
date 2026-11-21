// Unit tests for the sign-in loop brake and the proxy no-identity redirect (lib/api.js), and the
// Services route/help wiring.
import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { config, tooManySignInRedirects } from '../lib/api.js'
import { ROUTES } from '../lib/routes.js'

const here = dirname(fileURLToPath(import.meta.url))
const registry = JSON.parse(readFileSync(join(here, '..', 'help', 'registry.json'), 'utf8'))
const defaultUnauthorized = config.onUnauthorized

function memoryStorage() {
  const m = new Map()
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }
}
let assigned = []
beforeEach(() => {
  assigned = []
  globalThis.sessionStorage = memoryStorage()
  globalThis.location = { pathname: '/devices', search: '?q=x', assign: (u) => assigned.push(u) }
})

test('@feature:services PROXY_IDENTITY_MISSING goes to the explanation, never to /auth/login', () => {
  defaultUnauthorized({ code: 'PROXY_IDENTITY_MISSING', status: 401 })
  assert.deepEqual(assigned, ['/signed-out?reason=proxy'])
})

test('@feature:services an ordinary 401 still redirects to sign-in with the return path', () => {
  defaultUnauthorized({ code: 'AUTH_REQUIRED', status: 401 })
  assert.deepEqual(assigned, ['/auth/login?rd=%2Fdevices%3Fq%3Dx'])
})

test('@feature:services the loop brake trips on the 4th sign-in redirect within a minute', () => {
  const t0 = 1_000_000
  assert.equal(tooManySignInRedirects(t0), false)
  assert.equal(tooManySignInRedirects(t0 + 1000), false)
  assert.equal(tooManySignInRedirects(t0 + 2000), false)
  assert.equal(tooManySignInRedirects(t0 + 3000), true)
  // A minute later the window has moved on.
  globalThis.sessionStorage = memoryStorage()
  assert.equal(tooManySignInRedirects(t0 + 120_000), false)
})

test('@feature:services repeated AUTH_REQUIRED redirects end on the explanation page', () => {
  for (let i = 0; i < 4; i++) defaultUnauthorized({ code: 'AUTH_REQUIRED', status: 401 })
  assert.equal(assigned.at(-1), '/signed-out?reason=proxy')
  assert.equal(assigned.filter(u => u.startsWith('/auth/login')).length, 3)
})

test('@feature:services the brake is off (not broken) without storage', () => {
  globalThis.sessionStorage = { getItem() { throw new Error('denied') }, setItem() { throw new Error('denied') } }
  assert.equal(tooManySignInRedirects(), false)
})

test('@feature:services services route is admin-gated and documented; signed-out is public', () => {
  const svc = ROUTES.find(r => r.path === '/services')
  assert.equal(svc.perm, 'services.read')
  assert.ok(registry.screens.services.columns.guacamole, 'service cards have column help')
  assert.ok(registry.empty['noaccess.proxy'].title)
  const out = ROUTES.find(r => r.path === '/signed-out')
  assert.equal(out.public, true, '/signed-out must render without a session (the proxy logout lands there)')
  for (const code of ['PROXY_IDENTITY_MISSING', 'CONTROL_UNAVAILABLE', 'CONTROL_ACTION_NOT_ALLOWED', 'CONTROL_TARGET_NOT_FOUND']) {
    assert.ok(registry.errors[code], `${code} has error help`)
  }
})
