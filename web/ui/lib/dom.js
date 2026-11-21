/**
 * Safe DOM construction. Every screen builds markup through `h()`; nothing in the UI assigns
 * innerHTML/outerHTML (lint: std.web.unsafe-dom-insertion), so text from the API is always inert.
 *
 * Contract of h(tag, attrs, ...children):
 *  - `attrs` keys:
 *      class / className  → className (string, or array of strings/falsy, joined)
 *      on<Event>          → addEventListener (e.g. onClick, onInput, onKeydown)
 *      dataset            → object merged into el.dataset
 *      aria / data-* / role / any other string key → setAttribute
 *      boolean `true`     → attribute present ('' value); false/null/undefined → omitted
 *      value / checked / selected / disabled / hidden → set as properties
 *  - children: Node, string/number (→ text node), arrays (flattened), null/false (skipped).
 *  - `style` is rejected — the CSP forbids inline styles; use classes and tokens.
 */

const PROPS = new Set(['value', 'checked', 'selected', 'disabled', 'hidden', 'indeterminate', 'open'])

/**
 * @param {string} tag
 * @param {Record<string, any>|null} [attrs]
 * @param {...any} children
 * @returns {HTMLElement}
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag)
  if (attrs) applyAttrs(el, attrs)
  append(el, children)
  return el
}

/** Apply an attrs object (same rules as h) to an existing element. */
export function applyAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue
    if (k === 'style') throw new Error('inline style is not allowed (CSP); use a class')
    if (k === 'class' || k === 'className') {
      el.className = Array.isArray(v) ? v.filter(Boolean).join(' ') : String(v)
    } else if (k === 'dataset') {
      Object.assign(el.dataset, v)
    } else if (k.length > 2 && k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2).toLowerCase(), v)
    } else if (PROPS.has(k)) {
      el[k] = v
    } else {
      el.setAttribute(k, v === true ? '' : String(v))
    }
  }
}

/** Append children (same rules as h: null/false skipped, arrays flattened). Unlike the native
 *  Element.append, null never turns into the text "null". */
export function append(el, ...children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false || c === true) continue
    el.append(c instanceof Node ? c : document.createTextNode(String(c)))
  }
  return el
}

/** Replace all children of `el`. */
export function replace(el, ...children) {
  el.replaceChildren()
  return append(el, children)
}

/** Short-hand for a DocumentFragment of children. */
export function frag(...children) {
  const f = document.createDocumentFragment()
  return append(f, children)
}

let idSeq = 0
/** Unique, stable-per-load element id (for label/aria wiring). */
export const uid = (prefix = 'rh') => `${prefix}-${++idSeq}`
