// HELP-7: every route has a registry entry, every entry's doc page exists, and every help key that
// screens reference (field ids, empty states, column help, icons) resolves. Also checks the icon
// registry mirrors design/icons.json (THEME-5).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ROUTES } from '../lib/routes.js'
import { setRegistry, searchHelp, errorHelp, docPage, fieldHelp } from '../lib/help.js'
import { NAMES } from '../lib/icons.js'

const ui = join(dirname(fileURLToPath(import.meta.url)), '..')
const repo = join(ui, '..', '..')
const registry = JSON.parse(readFileSync(join(ui, 'help', 'registry.json'), 'utf8'))
const sources = [join(ui, 'app.js'), ...['lib', 'screens'].flatMap(d => readdirSync(join(ui, d)).filter(f => f.endsWith('.js')).map(f => join(ui, d, f)))]
const code = Object.fromEntries(sources.map(f => [f, readFileSync(f, 'utf8')]))
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
const all = Object.values(code).map(stripComments).join('\n')
setRegistry(registry)

test('@feature:help every route resolves to a registry entry with the required sections', () => {
  for (const r of [...ROUTES, { help: 'notfound' }, { help: 'noaccess' }]) {
    const s = registry.screens[r.help]
    assert.ok(s, `registry.screens.${r.help} missing`)
    for (const k of ['title', 'purpose', 'how_to', 'roles', 'doc']) assert.ok(s[k], `${r.help}.${k} missing`)
  }
})

test('@feature:help every doc link resolves to docs/user/<page>.md', () => {
  const docs = [...Object.values(registry.screens).map(s => s.doc), ...Object.values(registry.errors).map(e => e.doc).filter(Boolean)]
  for (const d of docs) assert.ok(existsSync(join(repo, 'docs', 'user', `${docPage(d)}.md`)), `missing doc for ${d}`)
  for (const p of ['overview', 'devices', 'enroll', 'groups', 'users', 'sessions', 'integration', 'logs', 'debug', 'settings', 'audit', 'getting-started']) {
    assert.ok(existsSync(join(repo, 'docs', 'user', `${p}.md`)), `docs/user/${p}.md missing`)
  }
})

test('@feature:devices @feature:enroll @feature:groups @feature:users @feature:settings every form field id has field help', () => {
  const ids = new Set()
  for (const m of all.matchAll(/field\(\{\s*id:\s*'([\w.]+)'/g)) ids.add(m[1])
  for (const m of all.matchAll(/checkList\(\{\s*id:\s*'([\w.]+)'/g)) ids.add(m[1])
  for (const m of all.matchAll(/fieldHelp\('([\w.]+)'\)/g)) ids.add(m[1])
  // dynamic ids built in screens: settings.<k> from SECTIONS and device.option_<name>
  for (const m of code[join(ui, 'screens', 'settings.js')].matchAll(/\{ k: '(\w+)'/g)) ids.add(`settings.${m[1]}`)
  for (const m of code[join(ui, 'screens', 'device-detail.js')].matchAll(/^\s+'?([\w-]+)'?: \{ kinds:/gm)) ids.add(`device.option_${m[1].replace(/-/g, '_')}`)
  assert.ok(ids.size > 40, `expected many field ids, found ${ids.size}`)
  const missing = [...ids].filter(id => !fieldHelp(id))
  assert.deepEqual(missing, [], 'field ids without help')
})

test('@feature:overview @feature:sessions @feature:logs empty-state keys used by screens exist', () => {
  const keys = new Set(['filtered'])
  for (const m of all.matchAll(/emptyKey:\s*'([\w.-]+)'/g)) keys.add(m[1])
  for (const m of all.matchAll(/emptyState\('([\w.-]+)'/g)) keys.add(m[1])
  for (const m of all.matchAll(/emptyHelp\('([\w.-]+)'\)/g)) keys.add(m[1])
  for (const m of all.matchAll(/liveTab\([^,]+, '([\w.-]+)'/g)) keys.add(m[1])
  for (const k of ['login.intro', 'login.none', 'sessions.mine', 'sessions.shared', 'sessions.all']) keys.add(k)
  for (const r of ['forbidden', 'route', 'signedout']) keys.add(`noaccess.${r}`)
  const missing = [...keys].filter(k => !registry.empty[k])
  assert.deepEqual(missing, [])
})

test('@feature:integration @feature:debug @feature:audit grid columns have ⓘ help unless marked help:false', () => {
  const missing = []
  for (const src of Object.values(code)) {
    for (const g of src.matchAll(/helpScreen:\s*'(\w+)'([\s\S]*?)columns:\s*\[([\s\S]*?)\n\s{4,6}\]/g)) {
      const screen = g[1]
      for (const c of g[3].matchAll(/\{ id: '([\w.]+)'(.*)/g)) {
        if (/help: false/.test(c[2])) continue
        if (!registry.screens[screen]?.columns?.[c[1]]) missing.push(`${screen}.${c[1]}`)
      }
    }
  }
  assert.deepEqual(missing, [])
})

test('@feature:help required error codes map to fix text (HELP-3)', () => {
  for (const c of ['DEVICE_NOT_FOUND', 'DEVICE_OFFLINE', 'SERVICE_NOT_FORWARDED', 'GUAC_UNAVAILABLE', 'AUTH_FORBIDDEN', 'VALIDATION_FAILED',
    'PRECONDITION_FAILED', 'RATE_LIMITED', 'ENROLL_CODE_INVALID', 'ENROLL_CODE_EXPIRED', 'GROUP_NOT_EMPTY', 'LAST_ADMIN', 'INTERNAL']) {
    const e = errorHelp(c)
    assert.ok(e?.title && e?.fix, c)
  }
  assert.equal(errorHelp('HTTP_404').title, registry.errors.NOT_FOUND.title, 'unknown 404 codes fall back to NOT_FOUND')
  assert.equal(errorHelp('TIMEOUT').title, registry.errors.NETWORK_OFFLINE.title)
  assert.equal(errorHelp('SOMETHING_NEW').title, registry.errors.INTERNAL.title)
})

test('@feature:help help search finds screens and error fixes', () => {
  assert.equal(searchHelp('enroll code')[0].key, 'enroll')
  assert.ok(searchHelp('last admin').some(r => r.kind === 'error' && r.key === 'LAST_ADMIN'))
  assert.deepEqual(searchHelp(''), [])
})

test('@feature:help icon registry mirrors design/icons.json and every icon used exists', () => {
  const json = JSON.parse(readFileSync(join(repo, 'design', 'icons.json'), 'utf8')).icons
  const kebab = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replace(/([a-zA-Z])(\d)/g, '$1-$2').toLowerCase()
  assert.deepEqual(Object.keys(NAMES).sort(), Object.keys(json).sort())
  for (const [n, v] of Object.entries(json)) assert.equal(NAMES[n], kebab(v.lucide), n)
  const used = new Set()
  for (const m of all.matchAll(/icon\('([\w.]+)'/g)) used.add(m[1])
  for (const m of all.matchAll(/icon:\s*'([\w.]+)'/g)) used.add(m[1])
  for (const m of JSON.stringify(registry).matchAll(/"icon":\s*"([\w.]+)"/g)) used.add(m[1])
  for (const k of ['entra', 'google', 'apple', 'facebook', 'github', 'oidc']) used.add(`domain.provider.${k}`)
  const missing = [...used].filter(n => !NAMES[n])
  assert.deepEqual(missing, [])
})

test('@feature:help no file other than lib/api.js calls fetch( or EventSource', () => {
  for (const [f, src] of Object.entries(code)) {
    if (f.endsWith(join('lib', 'api.js'))) continue
    assert.ok(!/\bfetch\(/.test(src), `${f} calls fetch`)
    assert.ok(!/new EventSource/.test(src), `${f} opens an EventSource`)
    assert.ok(!/\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=/.test(src), `${f} writes HTML`)
  }
})

test('@feature:users @feature:sessions help explains personal logins, sharing and why admins cannot join', () => {
  assert.match(registry.fields['profile.credentials'], /nobody — admins included — can read it/)
  assert.match(registry.screens.sessions.tips.join(' '), /Joining needs the owner's invitation/)
  assert.equal(registry.fields['sessions.share_viewer'], 'Viewers can only watch.')
  assert.ok(registry.fields['login.small_print'])
  for (const p of ['login', 'profile']) assert.ok(existsSync(join(repo, 'docs', 'user', `${p}.md`)), p)
})

test('@feature:help provider glyphs have token colors with contrast-checked "on" pairs', () => {
  const css = readFileSync(join(ui, 'tokens.css'), 'utf8')
  for (const k of ['entra', 'google', 'apple', 'facebook', 'github', 'oidc']) {
    assert.match(css, new RegExp(`--color-domain-provider-${k}:`), k)
    assert.match(css, new RegExp(`--color-domain-provider-on-${k}:`), `on-${k}`)
  }
})
