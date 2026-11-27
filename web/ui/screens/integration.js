/**
 * Integration (/integration) — is Guacamole wired up correctly? Overall status, one card per check
 * with how-to-fix hints, "Run checks", and a diagram of the request path.
 * Data: GET /api/v1/integration (last report), POST /api/v1/integration/test (run now).
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { page, button, badge, relTime, skeleton, errorState, emptyState, toast, toastError, infoTip } from '../lib/ui.js'
import { columnHelp } from '../lib/help.js'
import { durationMs } from '../lib/format.js'

const STATUS = {
  pass: { label: 'Passing', tone: 'success', icon: 'status.success' },
  warn: { label: 'Warning', tone: 'warning', icon: 'status.warning' },
  fail: { label: 'Failing', tone: 'danger', icon: 'domain.status.fail' },
  skip: { label: 'Skipped', tone: 'neutral', icon: 'status.info' },
  unknown: { label: 'Not checked yet', tone: 'neutral', icon: 'status.info' },
}
const HERO = {
  pass: ['Guacamole is ready', 'Every check passed. Sessions can be opened from any device page.'],
  warn: ['Working, with warnings', 'Sessions should open, but something needs attention. See the yellow checks below.'],
  fail: ['Sessions will fail', 'At least one check failed. Fix the red checks below, then run the checks again.'],
  unknown: ['Not checked yet', 'Run the checks to validate the Guacamole integration end to end.'],
}

/** Request path diagram: browser → RemoteHound → Guacamole → guacd → tunnel → device. */
function pathDiagram(checks) {
  const st = (ids) => {
    const found = checks.filter(c => ids.includes(c.id))
    if (!found.length) return 'unknown'
    if (found.some(c => c.status === 'fail')) return 'fail'
    if (found.some(c => c.status === 'warn')) return 'warn'
    return found.every(c => c.status === 'skip') ? 'unknown' : 'pass'
  }
  const nodes = [
    ['Browser', 'Operator, any device', 'unknown', 'domain.os.macos'],
    ['RemoteHound', 'Auth, connect tokens, proxy', st(['proxy.websocket', 'json_auth.clock']), 'domain.brand'],
    ['Guacamole', 'HTML5 client, JSON auth', st(['guacamole.reachable', 'guacamole.version', 'json_auth.roundtrip']), 'domain.nav.integration'],
    ['guacd', 'RDP / VNC / SSH engine', st(['guacd.reachable', 'recording.path']), 'domain.object.zap'],
    ['Tunnel listener', 'Port per device + service', st(['tunnel.listener']), 'domain.object.tunnel'],
    ['Device', 'ssh -R from the machine', 'unknown', 'domain.nav.devices'],
  ]
  return h('figure', { class: 'flow card', 'aria-labelledby': 'flow-cap' },
    h('figcaption', { id: 'flow-cap', class: 'card__title' }, 'How a session travels'),
    h('ol', { class: 'flow__list', role: 'list' }, nodes.map(([title, sub, s, ic], i) => h('li', { class: `flow__node flow__node--${s}` },
      h('span', { class: 'flow__icon', 'aria-hidden': 'true' }, icon(ic)),
      h('span', { class: 'flow__text' }, h('span', { class: 'flow__title' }, title), h('span', { class: 'flow__sub' }, sub)),
      s !== 'unknown' ? h('span', { class: 'sr-only' }, `: ${STATUS[s].label}`) : null,
      i < nodes.length - 1 ? h('span', { class: 'flow__arrow', 'aria-hidden': 'true' }, icon('domain.nav.forward', { size: 'sm' })) : null))),
    h('p', { class: 'flow__note muted' }, columnHelp('integration', 'path')))
}

export default function render(ctx) {
  const body = h('div', { class: 'integration' })
  const p = page({
    title: 'Guacamole integration',
    subtitle: 'RemoteHound uses Apache Guacamole to draw sessions. These checks prove each hop works.',
    helpKey: 'integration',
    actions: [button({ label: 'Run checks', icon: 'domain.action.run', variant: 'primary', permission: 'integration.test', busyLabel: 'Running…', onClick: run })],
  })
  append(p.body, body)

  async function run() {
    try {
      const r = await api.post('/api/v1/integration/test')
      paint(r.data)
      const o = r.data?.overall
      toast(o === 'pass' ? 'All checks passed' : o === 'warn' ? 'Checks finished with warnings' : 'Some checks failed', { tone: o === 'pass' ? 'success' : o === 'warn' ? 'warning' : 'danger' })
    } catch (err) { toastError(err) }
  }

  function paint(rep) {
    const overall = STATUS[rep.overall] ? rep.overall : 'unknown'
    const [title, text] = HERO[overall] || HERO.unknown
    const checks = rep.checks || []
    const counts = ['pass', 'warn', 'fail', 'skip'].map(s => [s, checks.filter(c => c.status === s).length]).filter(([, n]) => n)
    replace(body,
      h('section', { class: `hero hero--${STATUS[overall].tone}`, 'aria-labelledby': 'hero-h' },
        h('span', { class: 'hero__icon', 'aria-hidden': 'true' }, icon(STATUS[overall].icon, { size: 'xl' })),
        h('div', { class: 'hero__text' },
          h('h2', { id: 'hero-h', class: 'hero__title' }, title),
          h('p', null, text),
          h('p', { class: 'hero__meta' },
            rep.checked_at ? h('span', null, 'Last checked ', relTime(rep.checked_at)) : h('span', null, 'Never checked'),
            // Stock Guacamole does not report its version; "unknown" says nothing, so it is not shown.
            rep.guacamole_version && rep.guacamole_version !== 'unknown' ? h('span', null, 'Guacamole ', h('code', null, rep.guacamole_version)) : null,
            counts.length ? h('span', { class: 'chips' }, counts.map(([s, n]) => badge(`${n} ${STATUS[s].label.toLowerCase()}`, STATUS[s].tone))) : null))),
      checks.length
        ? h('ul', { class: 'checks', role: 'list' }, checks.map(c => {
          const s = STATUS[c.status] || STATUS.unknown
          const tip = columnHelp('integration', c.id)
          return h('li', { class: `check-card check-card--${s.tone}` },
            h('div', { class: 'check-card__head' },
              h('span', { class: 'check-card__icon', 'aria-hidden': 'true' }, icon(s.icon)),
              h('h3', { class: 'check-card__title' }, c.title || c.id, tip ? infoTip(tip, c.title || c.id) : null),
              badge(s.label, s.tone)),
            c.detail ? h('p', { class: 'check-card__detail' }, c.detail) : null,
            c.hint && c.status !== 'pass' ? h('div', { class: 'check-card__hint' }, h('strong', null, 'How to fix: '), c.hint) : null,
            h('p', { class: 'check-card__meta' }, h('code', null, c.id), c.latency_ms != null ? h('span', null, durationMs(c.latency_ms)) : null))
        }))
        : emptyState('integration'),
      pathDiagram(checks))
  }

  async function load() {
    replace(body, skeleton('cards', 4))
    try {
      const r = await api.get('/api/v1/integration', null, { signal: ctx.signal })
      paint(r.data || { overall: 'unknown', checks: [] })
    } catch (err) {
      if (err?.name !== 'AbortError') replace(body, errorState(err, load))
    }
  }
  load()
  return p.el
}
