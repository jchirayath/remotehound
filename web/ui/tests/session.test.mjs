// Unit tests for lib/session.js helpers.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { forgetGuacamole } from '../lib/session.js'

function fakeStorage(init) {
  const m = new Map(Object.entries(init))
  return {
    get length() { return m.size },
    key: (i) => [...m.keys()][i] ?? null,
    getItem: (k) => m.get(k) ?? null,
    removeItem: (k) => { m.delete(k) },
    keys: () => [...m.keys()],
  }
}

test('@feature:sessions sign-out forgets Guacamole auth tokens and nothing else', () => {
  const local = fakeStorage({ GUAC_AUTH: '{"authToken":"x"}', GUAC_AUTH_TOKEN: 'y', 'rh.theme': 'dark', GUAC_PREFERENCES: '{}' })
  const sess = fakeStorage({ GUAC_AUTH_TOKEN: 'z' })
  assert.equal(forgetGuacamole([local, sess, undefined]), 3)
  assert.deepEqual(local.keys().sort(), ['GUAC_PREFERENCES', 'rh.theme'])
  assert.deepEqual(sess.keys(), [])
})

test('@feature:sessions blocked storage does not throw', () => {
  const broken = { get length() { throw new Error('SecurityError') } }
  assert.equal(forgetGuacamole([broken]), 0)
})
