/**
 * Overlays: drawer/sheet, confirm dialog and toasts. Re-exported by ui.js — screens import from ui.js.
 *
 * All overlays use the native <dialog> element with showModal(), which gives focus trapping, inert
 * background, Escape to close and top-layer stacking for free. Focus returns to the element that
 * opened the overlay. On compact widths the drawer becomes a bottom sheet (CSS only).
 */
import { h, uid } from './dom.js'
import { icon } from './icons.js'

/**
 * Open a drawer (side panel; bottom sheet on phones).
 * @param {{title:string|Node, content:Node, footer?:Node, onClose?:()=>void, size?:'md'|'lg', className?:string, headerExtra?:Node}} opts
 * @returns {{el: HTMLDialogElement, body: HTMLElement, close: () => void, setTitle:(t:string)=>void}}
 */
export function drawer(opts) {
  const titleId = uid('drawer-title')
  const opener = document.activeElement
  const title = h('h2', { id: titleId, class: 'drawer__title' }, opts.title)
  const body = h('div', { class: 'drawer__body' }, opts.content)
  const closeBtn = h('button', { type: 'button', class: 'btn btn--ghost btn--icon', 'aria-label': 'Close', onClick: () => close() }, icon('action.close'))
  const el = h('dialog', { class: ['drawer', opts.size === 'lg' && 'drawer--lg', opts.className], 'aria-labeledby': titleId },
    h('div', { class: 'drawer__panel' },
      h('header', { class: 'drawer__header' }, title, opts.headerExtra || null, closeBtn),
      body,
      opts.footer ? h('footer', { class: 'drawer__footer' }, opts.footer) : null))
  let closed = false
  function close() {
    if (closed) return
    closed = true
    el.classList.add('is-closing')
    const done = () => { el.close(); el.remove(); opts.onClose?.(); if (opener?.focus) opener.focus() }
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) done()
    else setTimeout(done, 180)
  }
  el.addEventListener('cancel', (ev) => { ev.preventDefault(); close() })
  el.addEventListener('click', (ev) => { if (ev.target === el) close() })
  document.body.append(el)
  el.showModal()
  return { el, body, close, setTitle: (t) => { title.textContent = t } }
}

/**
 * Accessible confirmation dialog.
 * @param {{title:string, body?:string|Node, confirmLabel?:string, cancelLabel?:string,
 *          tone?:'danger'|'primary', typed?:string}} opts  typed: the user must type this text to enable confirm
 * @returns {Promise<boolean>}
 */
export function confirmDialog(opts) {
  return new Promise((resolve) => {
    const titleId = uid('confirm-title')
    const descId = uid('confirm-desc')
    const opener = document.activeElement
    const okBtn = h('button', { type: 'submit', class: ['btn', opts.tone === 'danger' ? 'btn--danger' : 'btn--primary'], value: 'ok' }, opts.confirmLabel || 'Confirm')
    let typedInput = null
    let typedField = null
    if (opts.typed) {
      okBtn.disabled = true
      const inputId = uid('confirm-typed')
      typedInput = h('input', { id: inputId, class: 'input', autocomplete: 'off', spellcheck: 'false',
        onInput: () => { okBtn.disabled = typedInput.value.trim() !== opts.typed } })
      typedInput.dataset.typed = '1'
      typedField = h('div', { class: 'field' },
        h('label', { for: inputId, class: 'field__label' }, 'Type ', h('strong', null, opts.typed), ' to confirm'),
        typedInput)
    }
    const form = h('form', { method: 'dialog', class: 'confirm__form' },
      h('h2', { id: titleId, class: 'confirm__title' }, opts.title),
      opts.body ? h('div', { id: descId, class: 'confirm__body' }, opts.body) : null,
      typedField,
      h('div', { class: 'confirm__actions' },
        h('button', { type: 'submit', class: 'btn btn--secondary', value: 'cancel', formnovalidate: true }, opts.cancelLabel || 'Cancel'),
        okBtn))
    const el = h('dialog', { class: 'confirm', 'aria-labeledby': titleId, 'aria-describedby': opts.body ? descId : null, role: 'alertdialog' }, form)
    el.addEventListener('close', () => {
      const ok = el.returnValue === 'ok'
      el.remove()
      if (opener?.focus) opener.focus()
      resolve(ok)
    })
    document.body.append(el)
    el.showModal()
    if (typedInput) typedInput.focus()
    else form.querySelector('button[value="cancel"]').focus()
  })
}

let toastRegion = null
function region() {
  if (!toastRegion) {
    toastRegion = h('div', { class: 'toasts', role: 'region', 'aria-label': 'Notifications' })
    document.body.append(toastRegion)
  }
  // keep toasts above any open modal dialog: move the region into the top-most dialog
  const open = [...document.querySelectorAll('dialog[open]')].pop()
  const host = open || document.body
  if (toastRegion.parentElement !== host) host.append(toastRegion)
  return toastRegion
}

const TONE_ICON = { success: 'status.success', danger: 'status.danger', warning: 'status.warning', info: 'status.info' }

/**
 * Show a toast. Errors stay until dismissed; others fade after `timeout` ms.
 * @param {string} message
 * @param {{tone?:'success'|'danger'|'warning'|'info', detail?:string, requestId?:string,
 *          action?:{label:string, onClick:()=>void}, timeout?:number}} [opts]
 */
export function toast(message, opts = {}) {
  const tone = opts.tone || 'info'
  const t = h('div', { class: `toast toast--${tone}`, role: tone === 'danger' ? 'alert' : 'status' },
    h('span', { class: 'toast__icon' }, icon(TONE_ICON[tone])),
    h('div', { class: 'toast__text' },
      h('p', { class: 'toast__msg' }, message),
      opts.detail ? h('p', { class: 'toast__detail' }, opts.detail) : null,
      opts.requestId ? h('p', { class: 'toast__rid' }, 'Request ID ', h('code', null, opts.requestId)) : null),
    opts.action ? h('button', { type: 'button', class: 'btn btn--ghost btn--sm', onClick: () => { opts.action.onClick(); dismiss() } }, opts.action.label) : null,
    h('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', 'aria-label': 'Dismiss notification', onClick: () => dismiss() }, icon('action.close', { size: 'sm' })))
  region().append(t)
  let gone = false
  function dismiss() {
    if (gone) return
    gone = true
    t.classList.add('is-leaving')
    setTimeout(() => t.remove(), 200)
  }
  const timeout = opts.timeout ?? (tone === 'danger' ? 0 : 5000)
  if (timeout) setTimeout(dismiss, timeout)
  return dismiss
}
