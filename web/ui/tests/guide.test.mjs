// Device setup guide (web/ui/guide/guide.js): only clean values reach the printed commands.  @feature:enroll
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { baseFromCommand, cleanGuideData, initialBase, MSG_DATA } from '../lib/guide-data.js'

const ok = { type: MSG_DATA, code: 'k7q2mx', base: 'https://rh.example.com', os: 'macos', name: 'Jane laptop', expires_at: '2026-11-26T17:00:00Z' }

test('a well-formed message is kept', () => {
  assert.deepEqual(cleanGuideData(ok), { code: 'k7q2mx', base: 'https://rh.example.com', os: 'macos', name: 'Jane laptop', expires: '2026-11-26T17:00:00Z' })
})

test('a bad or missing code leaves the guide blank', () => {
  for (const code of ['', 'K7Q2MX', 'k7q2m', 'k7q2mxx', 'k7q2m0', 'abc$de', 'k7q2ml']) {
    assert.equal(cleanGuideData({ ...ok, code }), null, code)
  }
  assert.equal(cleanGuideData({ ...ok, type: 'other' }), null)
  assert.equal(cleanGuideData('k7q2mx'), null)
  assert.equal(cleanGuideData(null), null)
})

test('an address that is not a plain server URL is dropped, never printed', () => {
  for (const base of ['javascript:alert(1)', 'https://evil.example.com/x;rm -rf ~', 'https://a b', 'ftp://x', 'https://x/$(id)']) {
    assert.equal(cleanGuideData({ ...ok, base }).base, '', base)
  }
  assert.equal(cleanGuideData({ ...ok, base: 'https://rh.example.com/' }).base, 'https://rh.example.com')
})

test('unknown OS shows both pages; the name loses control characters and is capped', () => {
  assert.equal(cleanGuideData({ ...ok, os: 'linux' }).os, '')
  assert.equal(cleanGuideData({ ...ok, os: 'windows' }).os, 'windows')
  assert.equal(cleanGuideData({ ...ok, name: 'a\nb\u0007c' }).name, 'abc')
  assert.equal(cleanGuideData({ ...ok, name: 'x'.repeat(100) }).name.length, 64)
})

test('the base is read from the server-built Windows command', () => {
  assert.equal(baseFromCommand('irm https://rh.example.com/e/k7q2mx | iex'), 'https://rh.example.com')
  assert.equal(baseFromCommand('irm https://rh.example.com:8443/rh/e/k7q2mx | iex'), 'https://rh.example.com:8443/rh')
  assert.equal(baseFromCommand('curl -fsSL https://rh.example.com/e/k7q2mx | sh'), '')
  assert.equal(baseFromCommand(''), '')
  assert.equal(baseFromCommand(undefined), '')
})

test('a page with no message uses its own origin, never an address from the URL', () => {
  assert.equal(initialBase({ protocol: 'file:', search: '?base=https://rh.example.com', origin: 'null' }), '')
  assert.equal(initialBase({ protocol: 'http:', search: '?base=javascript:x', origin: 'http://127.0.0.1:8080' }), 'http://127.0.0.1:8080')
  assert.equal(initialBase({ protocol: 'https:', search: '?base=https://evil.example.com', origin: 'https://rh.example.com' }), 'https://rh.example.com')
})

test('the page loads only same-origin files and no inline script or style (CSP)', () => {
  const html = readFileSync(new URL('../guide/device-setup.html', import.meta.url), 'utf8')
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/)
  assert.doesNotMatch(html, /\sstyle=/)
  assert.doesNotMatch(html, /(src|href)="(https?:)?\/\//)
  assert.match(html, /data-fill="code"/)
})
