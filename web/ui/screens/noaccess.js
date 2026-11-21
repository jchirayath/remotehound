/**
 * "No access" and "Signed out" — one screen, four reasons (query.reason):
 *   forbidden — GET /api/v1/me returned 403 (signed in to the IdP, but not a RemoteHound user / blocked)
 *   route     — the user's role lacks the permission for this screen (query.permission)
 *   signedout — the user just signed out (also the public /signed-out page a sign-in proxy's
 *               logout returns to). Offers the identity provider's own sign-out when configured
 *               (GET /auth/providers → idp_logout_url), for shared computers.
 *   proxy     — behind a sign-in proxy, requests arrive without an identity (PROXY_IDENTITY_MISSING,
 *               or the sign-in redirect loop brake tripped). Explains instead of looping.
 * Copy comes from the help registry (empty.noaccess.*).
 */
import { h, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { emptyHelp } from '../lib/help.js'
import { linkButton } from '../lib/ui.js'
import { log } from '../lib/log.js'

const REASONS = ['forbidden', 'route', 'signedout', 'proxy']

export default function render(ctx) {
  const reason = REASONS.includes(ctx.query?.reason) ? ctx.query.reason : (location.pathname === '/signed-out' ? 'signedout' : 'forbidden')
  const e = emptyHelp(`noaccess.${reason}`) || {}
  const err = ctx.query?.error
  const loginHref = `/auth/login?rd=${encodeURIComponent(reason === 'signedout' || reason === 'proxy' ? '/' : location.pathname + location.search)}`
  const calm = reason === 'signedout'
  ctx.setTitle?.(e.title || 'No access')
  const actions = h('div', { class: 'state__actions' },
    reason === 'route'
      ? linkButton({ href: '/', label: 'Go to overview', icon: 'nav.home', variant: 'primary' })
      : linkButton({ href: loginHref, label: calm || reason === 'proxy' ? 'Sign in again' : 'Sign in with another account', icon: 'object.user', variant: 'primary' }))
  if (calm) {
    // Optional IdP sign-out, e.g. Microsoft's, so the next person at this
    // computer is not signed in silently. Only an https URL from server config.
    api.get('/auth/providers').then(r => {
      const url = r?.data?.idp_logout_url
      if (typeof url === 'string' && url.startsWith('https://')) {
        append(actions, linkButton({ href: url, label: 'Also sign out of your identity provider', icon: 'action.logout', variant: 'secondary' }))
      }
    }).catch(e2 => log.debug('signedout.providers_unavailable', { code: e2?.code }))
  }
  return h('div', { class: 'page' },
    h('div', { class: 'state state--page' },
      h('div', { class: ['state__art', !calm && 'state__art--warning'], 'aria-hidden': 'true' }, icon(calm ? 'action.logout' : 'object.lock', { size: 'xl' })),
      h('h1', { class: 'state__title page__title', tabindex: '-1' }, e.title || (calm ? 'You are signed out' : 'You do not have access')),
      h('p', { class: 'state__body' }, e.body || ''),
      reason === 'route' && ctx.query.permission ? h('p', { class: 'state__meta' }, 'Needs permission ', h('code', null, ctx.query.permission)) : null,
      err?.requestId ? h('p', { class: 'state__meta' }, 'Request ID ', h('code', null, err.requestId)) : null,
      actions))
}
