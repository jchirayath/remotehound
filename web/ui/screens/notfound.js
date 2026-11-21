/**
 * 404 — the path does not match any screen. Offers the way back and the command palette; the hound
 * tilts its head at the unknown address.
 */
import { h } from '../lib/dom.js'
import { emptyHelp } from '../lib/help.js'
import { linkButton, button, mascot } from '../lib/ui.js'
import { openPalette } from '../lib/palette.js'

export default function render() {
  const e = emptyHelp('notfound') || {}
  return h('div', { class: 'page' },
    h('div', { class: 'state state--empty state--page' },
      h('div', { class: 'state__art state__art--mascot', 'aria-hidden': 'true' }, mascot('lost')),
      h('p', { class: 'state__code' }, '404'),
      h('h1', { class: 'state__title page__title', tabindex: '-1' }, e.title || 'Nothing at this address'),
      h('p', { class: 'state__body' }, e.body || 'The link may be old, or the item was deleted.'),
      h('p', { class: 'state__body mono' }, location.pathname),
      h('div', { class: 'state__actions' },
        linkButton({ href: '/', label: 'Go to overview', icon: 'nav.home', variant: 'primary' }),
        button({ label: 'Search', icon: 'action.search', variant: 'secondary', onClick: openPalette }))))
}
