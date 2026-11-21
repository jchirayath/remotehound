/**
 * Services (/services, admin) — is every part of the bundle running? One card per component
 * (RemoteHound, tunnel server, data store, Guacamole, guacd, plus any other container labelled for
 * control) with status, version, ports, recent problems and — when the rh-control helper is set
 * up — container state, Start / Stop / Restart and a log viewer. Below: the read-only Guacamole
 * configuration (there is no Guacamole admin UI: it runs with JSON auth and no user database).
 *
 * Data: GET /api/v1/services (refreshed every 15 s while open),
 *       GET /api/v1/services/{id}/logs?tail=N, POST /api/v1/services/{id}/actions/{action}.
 * Restarting RemoteHound itself answers 202 and the page waits for the API to come back.
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { can } from '../lib/session.js'
import { columnHelp } from '../lib/help.js'
import { page, button, badge, relTime, skeleton, errorState, toast, toastError, infoTip, kv, banner, drawer, confirmDialog, toggle, linkButton, copyButton } from '../lib/ui.js'
import { durationMs } from '../lib/format.js'

const STATUS = {
  ok: { label: 'Running', tone: 'success', icon: 'status.success' },
  degraded: { label: 'Degraded', tone: 'warning', icon: 'status.warning' },
  down: { label: 'Down', tone: 'danger', icon: 'domain.status.fail' },
  unknown: { label: 'Not checked', tone: 'neutral', icon: 'status.info' },
}
const HERO = {
  ok: ['Everything is running', 'All services answer. Devices can connect and sessions can open.'],
  degraded: ['Running, with problems', 'Something needs attention. See the yellow cards below.'],
  down: ['A service is down', 'At least one part of RemoteHound is not working. See the red cards below.'],
}
const STATE_TONE = { running: 'success', restarting: 'warning', paused: 'warning', created: 'neutral', exited: 'danger', dead: 'danger', removing: 'warning' }
const ACTION = {
  start: { label: 'Start', icon: 'domain.action.start', variant: 'secondary' },
  restart: { label: 'Restart', icon: 'domain.action.restart', variant: 'secondary' },
  stop: { label: 'Stop', icon: 'domain.action.stop', variant: 'danger' },
}

export default function render(ctx) {
  const body = h('div', { class: 'services' })
  const p = page({
    title: 'Services',
    subtitle: 'The parts of RemoteHound and whether each one is working. Admins can restart them here.',
    helpKey: 'services',
    actions: [button({ label: 'Refresh', icon: 'action.refresh', busyLabel: 'Refreshing…', onClick: () => load(true) })],
  })
  append(p.body, body)
  let painted = false
  let busy = false // an action is in flight: skip background refreshes

  async function load(manual = false) {
    if (!painted) replace(body, skeleton('cards', 5))
    try {
      const r = await api.get('/api/v1/services', null, { signal: ctx.signal })
      paint(r.data)
      if (manual) toast('Status refreshed', { tone: 'info', timeout: 2000 })
    } catch (err) {
      if (err?.name === 'AbortError') return
      if (!painted) replace(body, errorState(err, () => load(true)))
      else if (manual) toastError(err)
    }
  }

  const timer = setInterval(() => { if (!busy && document.visibilityState === 'visible') load() }, 15000)
  ctx.onCleanup(() => clearInterval(timer))

  function paint(rep) {
    painted = true
    const overall = STATUS[rep.overall] ? rep.overall : 'unknown'
    const [title, text] = HERO[overall] || HERO.degraded
    const counts = ['ok', 'degraded', 'down', 'unknown'].map(s => [s, rep.services.filter(x => x.status === s).length]).filter(([, n]) => n)
    replace(body,
      h('section', { class: `hero hero--${STATUS[overall].tone}`, 'aria-labelledby': 'svc-hero' },
        h('span', { class: 'hero__icon', 'aria-hidden': 'true' }, icon(STATUS[overall].icon, { size: 'xl' })),
        h('div', { class: 'hero__text' },
          h('h2', { id: 'svc-hero', class: 'hero__title' }, title),
          h('p', null, text),
          h('p', { class: 'hero__meta' },
            h('span', null, 'Updated ', relTime(rep.generated_at)),
            h('span', { class: 'chips' }, counts.map(([s, n]) => badge(`${n} ${STATUS[s].label.toLowerCase()}`, STATUS[s].tone)))))),
      controlBanner(rep.control),
      h('ul', { class: 'checks svc-grid', role: 'list', 'aria-label': 'Services' }, rep.services.map(s => card(s, rep.control))),
      guacCard(rep.guacamole))
  }

  function controlBanner(c) {
    if (!c.configured) {
      return banner('info', 'Status only', c.detail, linkButton({ href: '/docs/services.md', label: 'How to enable control', icon: 'nav.help', size: 'sm' }))
    }
    if (!c.reachable) return banner('warning', 'Container control is not answering', c.detail)
    return null
  }

  function card(s, control) {
    const st = STATUS[s.status] || STATUS.unknown
    const c = s.container
    const actions = h('div', { class: 'svc-card__actions' })
    if (c && control.reachable && can('services.control')) {
      for (const a of ['start', 'restart', 'stop']) {
        if (!c.actions.includes(a)) continue
        if (s.self_managed && a !== 'restart') continue
        const running = c.state === 'running'
        const disabled = (a === 'start' && running) || (a === 'stop' && !running)
        append(actions, button({ ...ACTION[a], size: 'sm', disabled, title: disabled ? `${s.name} is already ${running ? 'running' : 'stopped'}` : undefined,
          onClick: () => act(s, a) }))
      }
    }
    if (c && control.reachable && c.actions.includes('logs')) {
      append(actions, button({ label: 'View logs', icon: 'domain.nav.logs', size: 'sm', variant: 'ghost', onClick: () => openLogs(s) }))
    } else if (s.id === 'remotehound' && can('logs.read')) {
      append(actions, linkButton({ href: '/logs', label: 'Open logs', icon: 'domain.nav.logs', size: 'sm', variant: 'ghost' }))
    }
    const problems = s.problems || []
    return h('li', { class: `check-card check-card--${st.tone} svc-card`, 'aria-labelledby': `svc-${s.id}` },
      h('div', { class: 'check-card__head' },
        h('span', { class: 'check-card__icon', 'aria-hidden': 'true' }, icon(st.icon)),
        h('h3', { id: `svc-${s.id}`, class: 'check-card__title' }, s.name, columnHelp('services', s.id) ? infoTip(columnHelp('services', s.id), s.name) : null),
        badge(st.label, st.tone)),
      h('p', { class: 'svc-card__role muted' }, s.role),
      s.detail ? h('p', { class: 'check-card__detail' }, s.detail) : null,
      c ? h('div', { class: 'chips svc-card__container' },
        badge(c.state, STATE_TONE[c.state] || 'neutral'),
        c.health ? badge(`health: ${c.health}`, c.health === 'healthy' ? 'success' : c.health === 'unhealthy' ? 'danger' : 'warning') : null,
        c.restart_count ? badge(`${c.restart_count} restart${c.restart_count === 1 ? '' : 's'}`, 'warning') : null,
        c.state === 'running' && c.started_at ? h('span', { class: 'muted' }, 'up since ', relTime(c.started_at)) : null) : null,
      kv([
        s.version ? ['Version', h('code', null, s.version)] : null,
        s.latency_ms != null ? ['Response time', durationMs(s.latency_ms)] : null,
        c ? ['Container', h('code', null, c.name)] : null,
        c ? ['Image', h('code', { class: 'svc-card__image' }, c.image)] : null,
        c?.error ? ['Last start error', c.error] : null,
        ...Object.entries(s.facts || {}).map(([k, v]) => [k.replace(/_/g, ' '), h('code', null, v)]),
      ]),
      s.endpoints?.length ? h('ul', { class: 'svc-ports', role: 'list', 'aria-label': `${s.name} ports` }, s.endpoints.map(e =>
        h('li', null,
          badge(e.exposure, e.exposure === 'public' ? 'info' : 'neutral'),
          h('span', { class: 'svc-ports__label' }, e.label),
          h('code', null, e.address)))) : null,
      problemsList(s, problems),
      actions.childNodes.length ? actions : null)
  }

  function problemsList(s, problems) {
    if (!problems.length) return h('p', { class: 'svc-card__ok muted' }, icon('status.success', { size: 'sm' }), ' No warnings or errors in the last hour.')
    const item = (pr) => h('li', { class: `svc-problem svc-problem--${pr.severity}` },
      badge(pr.severity, pr.severity === 'error' ? 'danger' : 'warning'),
      pr.time ? h('span', { class: 'muted' }, relTime(pr.time)) : null,
      h('span', { class: 'svc-problem__text' }, pr.text))
    const first = problems.slice(0, 3)
    const rest = problems.slice(3)
    return h('div', { class: 'svc-problems' },
      h('h4', { class: 'svc-problems__title' }, `Recent problems (${problems.length})`),
      h('ul', { role: 'list' }, first.map(item)),
      rest.length ? h('details', null, h('summary', null, `Show ${rest.length} more`), h('ul', { role: 'list' }, rest.map(item))) : null)
  }

  async function act(s, action) {
    const self = s.self_managed
    const ok = await confirmDialog({
      title: `${ACTION[action].label} ${s.name}?`,
      body: action === 'stop'
        ? `${s.name} stops and stays stopped until someone starts it. ${s.id === 'guacd' || s.id === 'guacamole' ? 'Every open remote session ends and no new one can open.' : ''}`
        : self
          ? 'RemoteHound restarts: the console is unavailable for about 10 seconds and open sessions drop. Devices reconnect by themselves.'
          : `${s.name} restarts. ${s.id === 'guacd' || s.id === 'guacamole' ? 'Open remote sessions drop; people can reconnect after a few seconds.' : ''}`,
      confirmLabel: ACTION[action].label, tone: action === 'stop' || self ? 'danger' : 'primary',
      typed: action === 'stop' ? s.id : undefined,
    })
    if (!ok) return
    busy = true
    try {
      const r = await api.post(`/api/v1/services/${encodeURIComponent(s.id)}/actions/${action}`)
      if (r.status === 202) {
        toast(r.data?.detail || 'Restarting…', { tone: 'info' })
        await waitForComeback()
      } else {
        toast(`${s.name}: ${r.data?.state || 'done'}`, { tone: 'success' })
      }
    } catch (err) {
      toastError(err, `${ACTION[action].label} failed`)
    } finally {
      busy = false
      load()
    }
  }

  /** After a self-restart: poll until the API answers again (up to 90 s). */
  async function waitForComeback() {
    replace(body, h('div', { class: 'state state--page', 'aria-busy': 'true' },
      h('div', { class: 'state__art', 'aria-hidden': 'true' }, icon('domain.action.restart', { size: 'xl' })),
      h('h2', { class: 'state__title' }, 'RemoteHound is restarting'),
      h('p', { class: 'state__body' }, 'This page reconnects by itself.')))
    painted = false
    const until = Date.now() + 90_000
    await new Promise(res => setTimeout(res, 3000))
    while (Date.now() < until && !ctx.signal.aborted) {
      try {
        await api.get('/healthz', null, { signal: ctx.signal })
        toast('RemoteHound is back', { tone: 'success' })
        return
      } catch {
        await new Promise(res => setTimeout(res, 2000))
      }
    }
  }

  function openLogs(s) {
    const pre = h('div', { class: 'svc-logs', role: 'log', 'aria-label': `${s.name} log`, tabindex: '0' })
    let lines = []
    let problemsOnly = false
    const status = h('p', { class: 'muted svc-logs__status', role: 'status' }, 'Loading…')
    const show = () => {
      const shown = problemsOnly ? lines.filter(l => l.severity) : lines
      replace(pre, shown.length ? shown.map(l => h('div', { class: ['svc-logs__line', l.severity && `svc-logs__line--${l.severity}`] },
        h('span', { class: 'svc-logs__time' }, l.time ? new Date(l.time).toLocaleTimeString() : ''),
        h('span', { class: 'svc-logs__text' }, l.text))) : h('p', { class: 'muted' }, problemsOnly ? 'No warnings or errors in these lines.' : 'No output.'))
      status.textContent = `${shown.length} of ${lines.length} lines · newest at the bottom`
      pre.scrollTop = pre.scrollHeight
    }
    const fetchLogs = async () => {
      try {
        const r = await api.get(`/api/v1/services/${encodeURIComponent(s.id)}/logs`, { tail: 500 })
        lines = r.data || []
        show()
      } catch (err) {
        status.textContent = ''
        replace(pre, errorState(err, fetchLogs))
      }
    }
    drawer({
      title: `${s.name} logs`, size: 'lg',
      content: h('div', { class: 'svc-logs__wrap' },
        h('div', { class: 'svc-logs__toolbar' },
          toggle({ label: 'Warnings and errors only', checked: false, onChange: (v) => { problemsOnly = v; show() } }),
          button({ label: 'Reload', icon: 'action.refresh', size: 'sm', busyLabel: 'Loading…', onClick: fetchLogs }),
          copyButton(() => lines.map(l => `${l.time || ''} ${l.text}`).join('\n'), { label: 'Copy', compact: true })),
        status, pre,
        h('p', { class: 'muted svc-logs__note' }, 'Last 500 lines from the container, with secrets and tokens masked. Full history: the host\'s docker logs.')),
    })
    fetchLogs()
  }

  function guacCard(g) {
    const match = { pass: ['Matches Guacamole', 'success'], fail: ['DOES NOT match Guacamole', 'danger'], unknown: ['Not checked yet', 'neutral'] }[g.secret_matches] || ['Not checked yet', 'neutral']
    const help = (k) => columnHelp('services', `guac.${k}`)
    return h('section', { class: 'card svc-guac', 'aria-labelledby': 'svc-guac-h' },
      h('div', { class: 'card__head' },
        h('h2', { id: 'svc-guac-h', class: 'card__title' }, 'Guacamole configuration'),
        linkButton({ href: '/integration', label: 'Run integration checks', icon: 'domain.nav.integration', size: 'sm' })),
      h('p', { class: 'muted' }, 'Read-only. Guacamole has no admin screen in RemoteHound: it keeps no users or connections, so there is nothing to manage inside it. These values come from RemoteHound\'s configuration and the last integration check.'),
      kv([
        ['Version', g.version ? h('code', null, g.version) : null, help('version')],
        ['Sign-in extension', g.auth_extension, help('auth')],
        ['User database', g.user_database, help('database')],
        ['Shared JSON secret', h('span', { class: 'chips' }, h('code', null, g.secret_fingerprint || '—'), badge(match[0], match[1])), help('secret')],
        ['Internal URL', h('code', null, g.internal_url), help('url')],
        ['Public path', h('code', null, g.public_path)],
        ['guacd', h('code', null, g.guacd_address + (g.guacd_protocol ? `  (protocol ${g.guacd_protocol})` : ''))],
        ['Tunnel host guacd dials', h('code', null, g.tunnel_advertise_host), help('tunnel')],
        ['Session recording', g.recording_enabled ? h('span', null, 'On, to ', h('code', null, g.recording_path)) : 'Off (Settings)'],
        ['Last checked', g.checked_at ? relTime(g.checked_at) : 'Never'],
      ]))
  }

  load()
  return p.el
}
