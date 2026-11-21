/**
 * Overview (/) — fleet health at a glance: stat cards, Guacamole health, recent activity, quick
 * actions, and a getting-started checklist while no devices exist.
 * Data: GET /api/v1/overview (refreshed every 30 s while visible).
 */
import { h, replace } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { log } from '../lib/log.js'
import { session, can } from '../lib/session.js'
import { emptyHelp } from '../lib/help.js'
import { page, statCard, button, linkButton, badge, relTime, skeleton, errorState, emptyState, toast, toastError, mascot } from '../lib/ui.js'
import { number, plural, eventLabel as humanEvent } from '../lib/format.js'

const GUAC = {
  ok: { label: 'Healthy', tone: 'success', icon: 'status.success' },
  degraded: { label: 'Degraded', tone: 'warning', icon: 'status.warning' },
  down: { label: 'Down', tone: 'danger', icon: 'status.danger' },
  unknown: { label: 'Not checked', tone: 'neutral', icon: 'status.info' },
}

const OUTCOME_TONE = { success: 'success', failure: 'danger', denied: 'warning' }

/** Fallback for "Learn more" until /auth/providers answers (the server's RH_PROJECT_URL). */
const PROJECT_URL = 'https://github.com/jchirayath/remotehound'

/** What RemoteHound is for, above the numbers: one short paragraph and a link to the product site. */
function about() {
  const learnMore = h('a', { class: 'link about__link', href: PROJECT_URL, target: '_blank', rel: 'noopener' }, 'Learn more about RemoteHound', icon('domain.action.open', { size: 'sm' }), h('span', { class: 'sr-only' }, ' (opens in a new tab)'))
  api.get('/auth/providers').then(r => { const u = r?.data?.project_url; if (/^https?:\/\//.test(u || '')) learnMore.href = u }).catch(err => log.debug('overview.project_url_unavailable', { message: String(err?.message || err) }))
  return h('section', { class: 'about', 'aria-labelledby': 'about-h' },
    h('div', { class: 'about__art', 'aria-hidden': 'true' }, mascot('idle')),
    h('div', { class: 'about__text' },
      h('h2', { id: 'about-h', class: 'about__title' }, 'Reach your machines from a browser'),
      h('p', null, 'RemoteHound opens SSH, Remote Desktop and VNC sessions to your Linux, macOS and Windows machines in the browser. ',
        'Nothing to install and no inbound ports: each machine runs one command that opens an outbound tunnel. ',
        'Share a live session with a colleague, and every sign-in, connection and change is audited.'),
      learnMore))
}


function greeting() {
  const hr = new Date().getHours()
  const part = hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening'
  // No name from the sign-in provider: greet by the email's local part.
  const name = (session.me?.display_name || '').split(' ')[0] || (session.me?.email || '').split('@')[0]
  return name ? `${part}, ${name}` : part
}

export default function render(ctx) {
  const runChecks = async () => {
    try {
      const r = await api.post('/api/v1/integration/test')
      const o = r.data?.overall
      toast(o === 'pass' ? 'All integration checks passed' : 'Integration checks finished with problems', { tone: o === 'pass' ? 'success' : 'warning', action: { label: 'View', onClick: () => ctx.navigate('/integration') } })
      refresh()
    } catch (err) { toastError(err) }
  }
  const p = page({
    title: 'Overview',
    subtitle: greeting(),
    helpKey: 'overview',
    actions: [
      button({ label: 'Run integration checks', icon: 'domain.nav.integration', variant: 'secondary', permission: 'integration.test', onClick: runChecks, busyLabel: 'Checking…' }),
      can('enrollment.create') ? linkButton({ href: '/enroll', label: 'Enroll a device', icon: 'domain.nav.enroll', variant: 'primary' }) : null,
    ],
  })
  p.body.before(about())
  const body = p.body
  let first = true

  async function refresh() {
    if (first) replace(body, skeleton('cards', 6))
    try {
      const { data } = await api.get('/api/v1/overview', null, { signal: ctx.signal })
      replace(body, view(data))
      first = false
    } catch (err) {
      if (err?.name === 'AbortError') return
      if (first) replace(body, errorState(err, refresh))
    }
  }

  function view(o) {
    const g = GUAC[o.guacamole] || GUAC.unknown
    const offline = Math.max(0, (o.devices_total || 0) - (o.devices_online || 0) - (o.devices_pending || 0))
    const fleet = h('section', { class: 'fleet card', 'aria-labelledby': 'fleet-h' },
      h('div', { class: 'fleet__head' },
        h('h2', { id: 'fleet-h', class: 'card__title' }, 'Fleet'),
        h('a', { href: '/devices', class: 'link' }, 'All devices')),
      h('div', { class: 'fleet__numbers' },
        h('span', { class: 'fleet__big' }, number(o.devices_online || 0)),
        h('span', { class: 'fleet__of' }, `of ${plural(o.devices_total || 0, 'device')} online`)),
      h('meter', { class: 'fleet__meter', min: '0', max: String(Math.max(1, o.devices_total || 0)), value: String(o.devices_online || 0), 'aria-label': 'Devices online' }),
      h('ul', { class: 'fleet__legend', role: 'list' },
        h('li', null, h('span', { class: 'presence presence--online' }, h('span', { class: 'presence__dot', 'aria-hidden': 'true' }), h('a', { href: '/devices?online=true' }, `${number(o.devices_online || 0)} online`))),
        h('li', null, h('span', { class: 'presence presence--offline' }, h('span', { class: 'presence__dot', 'aria-hidden': 'true' }), h('a', { href: '/devices?online=false' }, `${number(offline)} offline`))),
        h('li', null, h('span', { class: 'presence presence--pending' }, h('span', { class: 'presence__dot', 'aria-hidden': 'true' }), h('a', { href: '/devices?status=pending' }, `${number(o.devices_pending || 0)} pending`)))))

    const stats = h('div', { class: 'stats' },
      statCard({ label: 'Active sessions', value: number(o.sessions_active || 0), sub: `${number(o.sessions_24h || 0)} in the last 24 h`, icon: 'domain.nav.sessions', href: can('session.read') ? '/sessions' : null, helpScreen: 'overview', helpKey: 'sessions_active' }),
      statCard({ label: 'Open enrolment codes', value: number(o.enrollments_open || 0), icon: 'domain.nav.enroll', href: can('enrollment.read') ? '/enroll' : null, helpScreen: 'overview', helpKey: 'enrollments_open', tone: 'accent' }),
      statCard({ label: 'Guacamole', value: badge(g.label, g.tone, g.icon), icon: 'domain.nav.integration', href: can('integration.read') ? '/integration' : null, helpScreen: 'overview', helpKey: 'guacamole', tone: g.tone === 'success' ? 'brand' : g.tone }),
      statCard({ label: 'Failing jobs', value: number(o.jobs_failing || 0), icon: 'domain.nav.debug', href: can('debug.read') ? '/debug' : null, helpScreen: 'overview', helpKey: 'jobs_failing', tone: o.jobs_failing ? 'danger' : 'brand' }))

    const activity = h('section', { class: 'card activity', 'aria-labelledby': 'act-h' },
      h('div', { class: 'card__head' }, h('h2', { id: 'act-h', class: 'card__title' }, 'Recent activity'),
        can('audit.read') ? h('a', { href: '/audit', class: 'link' }, 'Audit log') : null),
      (o.recent_activity || []).length
        ? h('ol', { class: 'feed', role: 'list' }, o.recent_activity.slice(0, 12).map(ev => h('li', { class: 'feed__item' },
          h('span', { class: `feed__dot feed__dot--${OUTCOME_TONE[ev.outcome] || 'neutral'}`, 'aria-hidden': 'true' }),
          h('div', { class: 'feed__text' },
            h('p', { class: 'feed__title' }, humanEvent(ev.event), ev.outcome && ev.outcome !== 'success' ? [' ', badge(ev.outcome, OUTCOME_TONE[ev.outcome] || 'neutral')] : null),
            h('p', { class: 'feed__meta' }, [ev.user_email || 'system', ev.resource].filter(Boolean).join(' · '))),
          relTime(ev.timestamp))))
        : emptyState('overview.activity'))

    const parts = [fleet, stats]
    if (!o.devices_total) parts.unshift(checklist(o))
    return h('div', { class: 'overview' }, h('div', { class: 'overview__main' }, parts), activity)
  }

  function checklist(o) {
    const e = emptyHelp('overview.getting_started') || { title: 'Get started', steps: [] }
    const done = {
      integration: o.guacamole === 'ok',
      group: (o.groups_total || 0) > 0,
      enroll: (o.devices_total || 0) > 0 || (o.enrollments_open || 0) > 0,
      connect: (o.sessions_24h || 0) > 0,
    }
    return h('section', { class: 'card checklist', 'aria-labelledby': 'gs-h' },
      h('div', { class: 'checklist__art checklist__art--mascot', 'aria-hidden': 'true' }, mascot('waiting')),
      h('div', null,
        h('h2', { id: 'gs-h', class: 'card__title' }, e.title),
        e.body ? h('p', { class: 'muted' }, e.body) : null,
        h('ol', { class: 'checklist__list' }, (e.steps || []).map(s => h('li', { class: ['checklist__item', done[s.id] && 'is-done'] },
          h('span', { class: 'checklist__tick', 'aria-hidden': 'true' }, done[s.id] ? icon('state.check', { size: 'sm' }) : null),
          h('span', { class: 'checklist__text' }, h('a', { href: s.href }, s.label), s.hint ? h('span', { class: 'checklist__hint' }, s.hint) : null),
          h('span', { class: 'sr-only' }, done[s.id] ? '(done)' : '(to do)'))))))
  }

  refresh()
  const t = setInterval(() => { if (!document.hidden) refresh() }, 30000)
  ctx.onCleanup(() => clearInterval(t))
  return p.el
}
