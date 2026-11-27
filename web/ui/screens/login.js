/**
 * Sign in (/login) — public page; renders WITHOUT a session (app.js skips /api/v1/me for it).
 * GET /auth/login sends people here when several sign-in providers are enabled.
 *
 * Data: GET /auth/providers → {mode, providers:[{id,name,kind}]}. Each provider is a plain link
 * (full navigation) to /auth/login/{id}?rd=<rd>, where rd is passed through only when it is a safe
 * same-origin path (router.safeReturnPath). No third-party logos: each provider gets a generic glyph
 * on its color.domain.provider.* token.
 */
import { h, replace } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { fieldHelp, emptyHelp } from '../lib/help.js'
import { skeleton, errorState, emptyState, banner, describeError, helpButton, mascot } from '../lib/ui.js'
import { safeReturnPath } from '../lib/router.js'

export const PROVIDER_KINDS = ['entra', 'google', 'apple', 'facebook', 'github', 'oidc']

/** Provider glyph tile, colored from the provider's domain token. */
export function providerMark(kind, name) {
  const k = PROVIDER_KINDS.includes(kind) ? kind : 'oidc'
  return h('span', { class: `provider-mark provider--${k}`, 'aria-hidden': 'true', title: name || k }, icon(`domain.provider.${k}`))
}

/** Build the provider sign-in URL, carrying a safe return path only. */
export function providerHref(id, rd) {
  const safe = safeReturnPath(rd)
  return `/auth/login/${encodeURIComponent(id)}${safe ? `?rd=${encodeURIComponent(safe)}` : ''}`
}

export default function render(ctx) {
  const rd = ctx.query?.rd
  const list = h('div', { class: 'login__providers' }, skeleton('rows', 2))
  const err = ctx.query?.error ? describeError({ code: String(ctx.query.error).slice(0, 64) }) : null

  async function load() {
    replace(list, skeleton('rows', 2))
    try {
      const r = await api.get('/auth/providers')
      if (!r.data || typeof r.data !== 'object') throw Object.assign(new Error('unexpected response'), { code: 'SERVICE_UNAVAILABLE', title: 'Sign-in options could not be loaded' })
      const { mode, providers = [] } = r.data
      if (mode === 'proxy' || mode === 'dev') {
        const safe = safeReturnPath(rd)
        replace(list, h('a', { class: 'provider-btn', href: `/auth/login${safe ? `?rd=${encodeURIComponent(safe)}` : ''}` },
          providerMark('oidc', 'Sign in'), h('span', { class: 'provider-btn__label' }, mode === 'dev' ? 'Continue (development sign-in)' : 'Continue with your organization'),
          icon('domain.nav.forward', { size: 'sm', className: 'provider-btn__go' })))
        return
      }
      if (!providers.length) { replace(list, emptyState('login.none')); return }
      replace(list, providers.map(pv => h('a', { class: `provider-btn provider-btn--${PROVIDER_KINDS.includes(pv.kind) ? pv.kind : 'oidc'}`, href: providerHref(pv.id, rd) },
        providerMark(pv.kind, pv.name),
        h('span', { class: 'provider-btn__label' }, `Continue with ${pv.name}`),
        icon('domain.nav.forward', { size: 'sm', className: 'provider-btn__go' }))))
    } catch (e) {
      replace(list, errorState(e, load))
    }
  }

  const intro = emptyHelp('login.intro') || {}
  load()
  return h('div', { class: 'login' },
    h('div', { class: 'login__card' },
      h('div', { class: 'login__hero', 'aria-hidden': 'true' }, mascot()),
      h('div', { class: 'login__head' },
        h('h1', { class: 'login__title page__title', tabindex: '-1' }, intro.title || 'Sign in'),
        helpButton('login', 'Help with signing in')),
      intro.body ? h('p', { class: 'muted' }, intro.body) : null,
      err ? banner('danger', err.title, err.fix) : null,
      list,
      h('p', { class: 'login__fine' }, icon('object.lock', { size: 'sm' }), fieldHelp('login.small_print'))))
}
