// Unit tests for route matching (lib/router.js) and the route table (lib/routes.js).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { match, compile, isAppPath, safeReturnPath, isSessionUrl } from '../lib/router.js'
import { ROUTES } from '../lib/routes.js'

const m = (p) => match(ROUTES, p)

test('@feature:overview root path matches the overview', () => {
  assert.equal(m('/').route.screen, 'overview')
  assert.equal(m('').route.screen, 'overview')
})

test('@feature:devices device list and detail with decoded params', () => {
  assert.equal(m('/devices').route.screen, 'devices')
  assert.equal(m('/devices/').route.screen, 'devices', 'trailing slash ignored')
  const d = m('/devices/dev_8f3k%20x?tab=logs')
  assert.equal(d.route.screen, 'device-detail')
  assert.equal(d.params.id, 'dev_8f3k x')
  assert.equal(m('/devices/a/b'), null)
})

test('@feature:enroll @feature:groups @feature:users @feature:sessions @feature:integration @feature:logs @feature:debug @feature:settings @feature:audit every screen route resolves', () => {
  for (const [path, screen] of [['/enroll', 'enroll'], ['/groups', 'groups'], ['/users', 'users'], ['/sessions', 'sessions'],
    ['/integration', 'integration'], ['/logs', 'logs'], ['/debug', 'debug'], ['/settings', 'settings'], ['/audit', 'audit']]) {
    assert.equal(m(path)?.route.screen, screen, path)
  }
  assert.equal(m('/nope'), null, 'unknown paths fall through to the 404 screen')
})

test('@feature:devices compile escapes regex characters', () => {
  const c = compile('/a.b/:id')
  assert.equal(c.re.test('/a.b/1'), true)
  assert.equal(c.re.test('/aXb/1'), false)
  assert.deepEqual(c.keys, ['id'])
})

test('@feature:help server paths are never handled by the SPA', () => {
  assert.equal(isAppPath('/devices'), true)
  assert.equal(isAppPath('/api/v1/me'), false)
  assert.equal(isAppPath('/auth/login'), false)
  assert.equal(isAppPath('/docs/devices'), false)
  assert.equal(isAppPath('/guacamole/#/client/x'), false)
  assert.equal(isAppPath('/ui/app.css'), false)
  assert.equal(isAppPath('/e/k7q2mx'), false)
})

test('@feature:help @feature:users /login is a public route and /profile is reachable', () => {
  const login = m('/login?rd=%2Fdevices')
  assert.equal(login.route.screen, 'login')
  assert.equal(login.route.public, true, 'the sign-in page must render without a session')
  const prof = m('/profile')
  assert.equal(prof.route.screen, 'profile')
  assert.ok(!prof.route.public)
  // Only pages that show no data may be public: sign-in, and the signed-out page a sign-in
  // proxy's logout returns to (it must render with no session at all).
  assert.deepEqual(ROUTES.filter(r => r.public).map(r => r.path).sort(), ['/login', '/signed-out'], 'only sign-in and signed-out are public')
})

test('@feature:help safeReturnPath only passes same-origin paths through', () => {
  assert.equal(safeReturnPath('/devices/dev_1?tab=logs'), '/devices/dev_1?tab=logs')
  assert.equal(safeReturnPath('/'), '/')
  for (const bad of ['//evil.example', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', '', null, undefined, 'devices', '/a\nb', '/\u0000x']) {
    assert.equal(safeReturnPath(bad), null, String(bad))
  }
})

test('@feature:sessions @feature:devices session URLs from connect/join must be same-origin', () => {
  assert.equal(isSessionUrl('/guacamole/?data=abc#/client/x'), true)
  assert.equal(isSessionUrl('https://guac.example/x'), false)
  assert.equal(isSessionUrl('//guac.example/x'), false)
  assert.equal(isSessionUrl(undefined), false)
})
