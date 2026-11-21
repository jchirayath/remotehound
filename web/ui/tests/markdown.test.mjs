// Unit tests for the safe Markdown subset renderer (lib/markdown.js).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse, parseInline, safeHref, slug } from '../lib/markdown.js'

test('@feature:help parses headings, paragraphs, lists and code', () => {
  const b = parse('# Title\n\nSome *text* here\nwrapped.\n\n- one\n- two\n\n1. first\n2. second\n\n```sh\ncurl -sL x | sh\n```\n\n> note\n\n---')
  assert.deepEqual(b.map(x => x.t), ['h', 'p', 'ul', 'ol', 'code', 'quote', 'hr'])
  assert.equal(b[0].level, 1)
  assert.equal(b[2].items.length, 2)
  assert.equal(b[4].lang, 'sh')
  assert.equal(b[4].v, 'curl -sL x | sh')
  assert.deepEqual(b[1].c.map(n => n.t), ['text', 'em', 'text'])
})

test('@feature:help inline code, bold and links', () => {
  const n = parseInline('Use `ssh -R` and **always** read [the guide](/docs/devices).')
  assert.deepEqual(n.map(x => x.t), ['text', 'code', 'text', 'strong', 'text', 'link', 'text'])
  assert.equal(n[5].href, '/docs/devices')
})

test('@feature:help raw HTML stays literal text (never parsed)', () => {
  const b = parse('<img src=x onerror=alert(1)> <script>alert(1)</script>')
  assert.equal(b[0].t, 'p')
  assert.equal(b[0].c[0].t, 'text')
  assert.match(b[0].c[0].v, /<script>/)
})

test('@feature:help links are restricted to https and relative URLs', () => {
  assert.equal(safeHref('https://example.com/x'), 'https://example.com/x')
  assert.equal(safeHref('/docs/enroll'), '/docs/enroll')
  assert.equal(safeHref('devices.md'), 'devices.md')
  assert.equal(safeHref('#troubleshooting'), '#troubleshooting')
  assert.equal(safeHref('javascript:alert(1)'), null)
  assert.equal(safeHref('JaVaScRiPt:alert(1)'), null)
  assert.equal(safeHref('data:text/html,<b>x</b>'), null)
  assert.equal(safeHref('http://insecure.example'), null)
  assert.equal(safeHref('//evil.example/x'), null)
  assert.equal(safeHref('vbscript:x'), null)
  const n = parseInline('[click](javascript:alert(1))')
  assert.equal(n[0].t, 'em', 'an unsafe link degrades to plain emphasised text')
})

test('@feature:help slugs for heading anchors', () => {
  assert.equal(slug('How a session travels!'), 'how-a-session-travels')
})
