// Unit tests for the data module (lib/api.js) with a stubbed fetch.
import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { api, config, ApiError, parseProblem, pointerToKey, buildUrl, setCsrfToken, apiEvents } from '../lib/api.js'

let calls = []
let queue = []
const res = (status, body, headers = {}) => new Response(body === null ? null : typeof body === 'string' ? body : JSON.stringify(body), {
  status, headers: { 'Content-Type': typeof body === 'string' ? 'text/html' : (status >= 400 ? 'application/problem+json' : 'application/json'), ...headers },
})
globalThis.fetch = async (url, init) => {
  calls.push({ url, init })
  const next = queue.shift()
  if (next instanceof Error) throw next
  return next
}
beforeEach(() => { calls = []; queue = []; config.onUnauthorized = () => {}; setCsrfToken('csrf-1') })

test('@feature:devices success bodies resolve to {data, meta}', async () => {
  queue.push(res(200, { data: [{ id: 'dev_1' }], meta: { next_page_token: 'p2' } }, { ETag: '"e1"', 'X-Request-Id': 'r1' }))
  const r = await api.get('/api/v1/devices', { q: 'lap', online: '', page_token: undefined })
  assert.deepEqual(r.data, [{ id: 'dev_1' }])
  assert.equal(r.meta.next_page_token, 'p2')
  assert.equal(r.etag, '"e1"')
  assert.equal(r.requestId, 'r1')
  assert.equal(calls[0].url, '/api/v1/devices?q=lap', 'empty filters are dropped')
  assert.equal(calls[0].init.credentials, 'same-origin')
  assert.equal(calls[0].init.headers['X-CSRF-Token'], undefined, 'no CSRF header on GET')
})

test('@feature:help problem+json is parsed into one typed ApiError', async () => {
  queue.push(res(422, { type: 'about:blank', title: 'Invalid', status: 422, code: 'VALIDATION_FAILED', detail: 'fix it', request_id: 'req-9',
    errors: [{ pointer: '/name', code: 'too_long', detail: 'At most 64 characters' }, { pointer: '/services/0/remote_port', detail: 'bad' }] }))
  await assert.rejects(api.post('/api/v1/groups', { name: 'x' }), (e) => {
    assert.ok(e instanceof ApiError)
    assert.equal(e.status, 422)
    assert.equal(e.code, 'VALIDATION_FAILED')
    assert.equal(e.requestId, 'req-9')
    assert.equal(e.detail, 'fix it')
    assert.deepEqual(e.fieldErrors, { name: 'At most 64 characters', 'services.0.remote_port': 'bad' })
    assert.equal(e.retryable, false)
    return true
  })
})

test('@feature:groups mutations send CSRF, request id and idempotency key', async () => {
  queue.push(res(201, { data: { id: 'grp_1' } }))
  await api.post('/api/v1/groups', { name: 'Lab' })
  const h = calls[0].init.headers
  assert.equal(h['X-CSRF-Token'], 'csrf-1')
  assert.match(h['X-Request-Id'], /[0-9a-f-]{36}/)
  assert.match(h['Idempotency-Key'], /[0-9a-f-]{36}/)
  assert.notEqual(h['X-Request-Id'], h['Idempotency-Key'])
  assert.equal(h['Content-Type'], 'application/json')
  assert.equal(calls[0].init.body, '{"name":"Lab"}')
})

test('@feature:settings PATCH is a merge patch with If-Match; 412 surfaces as PRECONDITION_FAILED', async () => {
  queue.push(res(412, { title: 'Conflict', status: 412, code: 'PRECONDITION_FAILED', request_id: 'r2' }))
  await assert.rejects(api.patch('/api/v1/settings', { log_level: 'DEBUG' }, '"v7"'), (e) => e.status === 412 && e.code === 'PRECONDITION_FAILED')
  const h = calls[0].init.headers
  assert.equal(h['If-Match'], '"v7"')
  assert.equal(h['Content-Type'], 'application/merge-patch+json')
  assert.equal(h['Idempotency-Key'], undefined, 'idempotency key only on POST')
})

test('@feature:users LAST_ADMIN conflict keeps its stable code', async () => {
  queue.push(res(409, { title: 'Last admin', status: 409, code: 'LAST_ADMIN', request_id: 'r3' }))
  await assert.rejects(api.del('/api/v1/users/usr_1'), (e) => e.code === 'LAST_ADMIN' && e.status === 409)
})

test('@feature:debug idempotent GETs retry once on 503, then map non-JSON errors to INTERNAL', async () => {
  queue.push(res(503, '<html>bad gateway</html>', { 'X-Request-Id': 'rx' }), res(503, '<html>bad gateway</html>', { 'X-Request-Id': 'ry' }))
  await assert.rejects(api.get('/api/v1/debug/runtime'), (e) => e.code === 'INTERNAL' && e.status === 503 && e.requestId === 'ry' && e.retryable)
  assert.equal(calls.length, 2)
})

test('@feature:sessions a mutation is never retried automatically', async () => {
  queue.push(res(503, '<html>x</html>'))
  await assert.rejects(api.post('/api/v1/sessions/ses_1/terminate'), (e) => e.status === 503)
  assert.equal(calls.length, 1)
})

test('@feature:overview offline maps to NETWORK_OFFLINE and fires a network event', async () => {
  let online = null
  apiEvents.addEventListener('network', (ev) => { online = ev.detail.online }, { once: true })
  queue.push(new TypeError('Failed to fetch'), new TypeError('Failed to fetch'))
  await assert.rejects(api.get('/api/v1/overview'), (e) => e.code === 'NETWORK_OFFLINE' && e.status === 0 && e.retryable)
  assert.equal(online, false)
  queue.push(res(200, { data: {} }))
  await api.get('/api/v1/overview')
})

test('@feature:enroll 401 calls the unauthorised hook (sign-in redirect)', async () => {
  let called = false
  config.onUnauthorized = () => { called = true }
  queue.push(res(401, { title: 'Sign in', status: 401, code: 'AUTH_REQUIRED', request_id: 'r4' }))
  await assert.rejects(api.get('/api/v1/enrollments'), (e) => e.code === 'AUTH_REQUIRED')
  assert.equal(called, true)
})

test('@feature:integration 204 resolves with null data', async () => {
  queue.push(new Response(null, { status: 204 }))
  const r = await api.del('/api/v1/enrollments/enr_1')
  assert.equal(r.data, null)
  assert.equal(r.status, 204)
})

test('@feature:logs buildUrl and pointerToKey helpers', async () => {
  assert.equal(buildUrl('/api/v1/logs', { source: 'client', level: '', q: 'a b', limit: 500 }), '/api/v1/logs?source=client&q=a+b&limit=500')
  assert.equal(pointerToKey('/roles_map/a~1b'), 'roles_map.a/b')
  const e = await parseProblem(new Response('nope', { status: 404, statusText: 'Not Found' }))
  assert.equal(e.code, 'HTTP_404')
})
