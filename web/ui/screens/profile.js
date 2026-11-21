/**
 * Profile (/profile) — your theme, the sign-in methods linked to your account, and your saved
 * personal logins for devices.
 *
 * Data: session.me (identities[], providers[]) refreshed from GET /api/v1/me; PUT /api/v1/me/preferences;
 * linking is a full navigation to /auth/link/{provider}; DELETE /api/v1/me/identities/{provider}
 * (409 LAST_ADMIN when it is your last method); GET/PUT/DELETE /api/v1/me/credentials[/{device_id}/{service}].
 */
import { h, replace, append } from '../lib/dom.js'
import { icon } from '../lib/icons.js'
import { api } from '../lib/api.js'
import { session, can } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import { setTheme, currentTheme, MODES } from '../lib/theme.js'
import { page, segmented, grid, button, linkButton, badge, relTime, confirmDialog, toast, toastError, skeleton, errorState, emptyState, banner, deviceLink } from '../lib/ui.js'
import { serviceLabel } from '../lib/format.js'
import { openCredentialForm } from './credential-form.js'
import { providerMark } from './login.js'

export default function render(ctx) {
  const me = session.me
  const p = page({ title: 'Profile', subtitle: me.display_name ? `${me.display_name} · ${me.email}` : me.email, helpKey: 'profile' })

  /* theme */
  const themeCard = h('section', { class: 'card', 'aria-labelledby': 'pf-theme' },
    h('h2', { id: 'pf-theme', class: 'card__title' }, 'Appearance'),
    h('p', { class: 'muted' }, fieldHelp('profile.theme')),
    segmented({
      label: 'Theme', value: currentTheme(),
      options: MODES.map(m => ({ value: m, label: m[0].toUpperCase() + m.slice(1), icon: `domain.theme.${m}` })),
      onChange: async (m) => {
        try { await setTheme(m); toast('Theme saved', { tone: 'success', timeout: 2000 }) } catch (err) { toastError(err, 'Theme saved on this device only') }
      },
    }),
    h('dl', { class: 'kv' },
      h('div', { class: 'kv__row' }, h('dt', null, 'Role'), h('dd', null, badge(me.role, me.role === 'admin' ? 'brand' : me.role === 'operator' ? 'info' : 'neutral'))),
      h('div', { class: 'kv__row' }, h('dt', null, 'Signed in with'), h('dd', null, me.auth_mode === 'proxy' ? 'Your organisation’s sign-in proxy' : me.auth_mode === 'dev' ? 'Development sign-in' : 'Your identity provider'))))

  /* sign-in methods */
  const methodsBody = h('div', { class: 'methods' })
  const methodsCard = h('section', { class: 'card', 'aria-labelledby': 'pf-methods' },
    h('h2', { id: 'pf-methods', class: 'card__title' }, 'Sign-in methods'),
    h('p', { class: 'muted' }, fieldHelp('profile.identities')),
    methodsBody)

  function paintMethods() {
    const providers = me.providers || []
    const identities = me.identities || []
    const nameOf = (id) => providers.find(x => x.id === id)?.name || id
    const kindOf = (id) => providers.find(x => x.id === id)?.kind || 'oidc'
    const linked = new Set(identities.map(i => i.provider))
    if (me.auth_mode !== 'oauth' && !identities.length) {
      replace(methodsBody, banner('info', 'Managed by your organisation', fieldHelp('profile.identities_managed')))
      return
    }
    replace(methodsBody,
      h('ul', { class: 'methods__list', role: 'list' },
        identities.map(i => h('li', { class: 'method' },
          providerMark(kindOf(i.provider), nameOf(i.provider)),
          h('div', { class: 'method__text' }, h('span', { class: 'method__name' }, nameOf(i.provider)),
            h('span', { class: 'method__sub' }, i.email || '', i.linked_at ? [i.email ? ' · ' : '', 'linked ', relTime(i.linked_at)] : null)),
          badge('Linked', 'success', 'state.check'),
          button({ label: 'Unlink', icon: 'domain.action.unlink', variant: 'ghost', size: 'sm', onClick: () => unlink(i, nameOf(i.provider)) }))),
        providers.filter(pv => !linked.has(pv.id)).map(pv => h('li', { class: 'method method--available' },
          providerMark(pv.kind, pv.name),
          h('div', { class: 'method__text' }, h('span', { class: 'method__name' }, pv.name), h('span', { class: 'method__sub' }, 'Not linked')),
          linkButton({ href: `/auth/link/${encodeURIComponent(pv.id)}`, label: 'Link', icon: 'object.link', variant: 'secondary', size: 'sm' })))),
      !providers.length && !identities.length ? emptyState('profile.identities') : null)
  }

  async function unlink(i, name) {
    if (!(await confirmDialog({ title: `Unlink ${name}?`, body: `You will no longer be able to sign in with ${name}${i.email ? ` (${i.email})` : ''}. You can link it again later.`, confirmLabel: 'Unlink', tone: 'danger' }))) return
    try {
      await api.del(`/api/v1/me/identities/${encodeURIComponent(i.provider)}`)
      toast(`${name} unlinked`, { tone: 'success' })
      const r = await api.get('/api/v1/me')
      Object.assign(me, { identities: r.data.identities || [], providers: r.data.providers || [] })
      paintMethods()
    } catch (err) {
      // 409 LAST_ADMIN here means "this is your last sign-in method": show the server's message.
      if (err.status === 409) toast('This sign-in method cannot be removed', { tone: 'warning', detail: err.detail || fieldHelp('profile.last_method'), requestId: err.requestId })
      else toastError(err)
    }
  }

  /* personal logins */
  const credsCard = h('section', { class: 'section', 'aria-labelledby': 'pf-creds' },
    h('div', { class: 'section-head' },
      h('div', null, h('h2', { id: 'pf-creds', class: 'section__title' }, 'My saved logins'), h('p', { class: 'muted' }, fieldHelp('profile.credentials'))),
      can('device.connect') ? button({ label: 'Save a login', icon: 'action.add', variant: 'primary', onClick: () => openCredentialForm({ onSaved: () => creds.reload() }) }) : null))
  const creds = grid({
    label: 'My saved logins',
    helpScreen: 'profile',
    emptyKey: 'profile.credentials',
    searchable: false,
    rowKey: (c) => `${c.device_id}/${c.service}`,
    initialSort: { id: 'device_name', dir: 'asc' },
    onRowClick: (c) => openCredentialForm({ existing: c, onSaved: () => creds.reload() }),
    load: ({ signal }) => api.get('/api/v1/me/credentials', null, { signal }),
    columns: [
      { id: 'device_name', label: 'Device', primary: true, render: (c) => deviceLink(c) },
      { id: 'service', label: 'Service', value: (c) => serviceLabel(c.service), render: (c) => h('span', { class: 'os' }, icon(`domain.service.${['ssh', 'rdp', 'vnc'].includes(c.service) ? c.service : 'ssh'}`, { size: 'sm' }), serviceLabel(c.service)) },
      { id: 'username', label: 'Username', className: 'mono' },
      { id: 'updated_at', label: 'Saved', render: (c) => relTime(c.updated_at) },
      { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (c) => button({ label: 'Edit', icon: 'action.edit', variant: 'ghost', size: 'sm', onClick: () => openCredentialForm({ existing: c, onSaved: () => creds.reload() }) }) },
    ],
  })
  credsCard.append(creds.el)

  async function loadMethods() {
    replace(methodsBody, skeleton('rows', 2))
    try {
      const r = await api.get('/api/v1/me', null, { signal: ctx.signal })
      Object.assign(me, { identities: r.data.identities || [], providers: r.data.providers || [] })
      paintMethods()
    } catch (err) {
      if (err?.name !== 'AbortError') replace(methodsBody, errorState(err, loadMethods))
    }
  }
  loadMethods()

  append(p.body, h('div', { class: 'split' }, themeCard, methodsCard), credsCard)
  return p.el
}
