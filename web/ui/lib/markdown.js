/**
 * Minimal, safe Markdown renderer for help text and docs/user/*.md (CORE-16).
 *
 * Supported subset: ATX headings (# … ####), paragraphs, unordered (- * +) and ordered (1.) lists,
 * fenced code blocks (```), block quotes (>), horizontal rules (---), inline `code`, **bold**,
 * *italic*, and [links](url). Anything else is rendered as literal text.
 *
 * Safety model: `parse()` produces a plain AST; `render()` turns it into DOM with createElement and
 * text nodes only — no HTML is ever parsed, so raw HTML in the source shows up as text.
 * Links are kept only if `safeHref()` accepts them (https, root-relative, relative paths, #anchors);
 * anything else (javascript:, data:, http:, protocol-relative //host) degrades to plain text.
 */

/** @param {string} url @returns {string|null} the URL if allowed, else null */
export function safeHref(url) {
  const u = String(url || '').trim()
  if (/^https:\/\/[^\s]+$/i.test(u)) return u
  if (/^\/(?!\/)[^\s]*$/.test(u)) return u
  if (/^#[\w-]+$/.test(u)) return u
  if (/^(\.{1,2}\/)?[\w-][\w./-]*(#[\w-]+)?$/.test(u) && !u.includes(':')) return u
  return null
}

/**
 * Parse inline Markdown into nodes.
 * @param {string} src
 * @returns {Array<{t:'text'|'code'|'strong'|'em'|'link', v?:string, href?:string, c?:any[]}>}
 */
export function parseInline(src) {
  const out = []
  let text = ''
  const flush = () => { if (text) { out.push({ t: 'text', v: text }); text = '' } }
  let i = 0
  while (i < src.length) {
    const ch = src[i]
    if (ch === '\\' && i + 1 < src.length && /[\\`*_[\]()#>-]/.test(src[i + 1])) { text += src[i + 1]; i += 2; continue }
    if (ch === '`') {
      const end = src.indexOf('`', i + 1)
      if (end > i) { flush(); out.push({ t: 'code', v: src.slice(i + 1, end) }); i = end + 1; continue }
    }
    if (ch === '*' && src[i + 1] === '*') {
      const end = src.indexOf('**', i + 2)
      if (end > i + 2) { flush(); out.push({ t: 'strong', c: parseInline(src.slice(i + 2, end)) }); i = end + 2; continue }
    }
    if ((ch === '*' || ch === '_') && src[i + 1] !== ch && src[i + 1] !== ' ') {
      const end = src.indexOf(ch, i + 1)
      if (end > i + 1 && src[end - 1] !== ' ') { flush(); out.push({ t: 'em', c: parseInline(src.slice(i + 1, end)) }); i = end + 1; continue }
    }
    if (ch === '[') {
      const close = src.indexOf('](', i + 1)
      const end = close > i ? src.indexOf(')', close + 2) : -1
      if (close > i && end > close) {
        flush()
        const label = parseInline(src.slice(i + 1, close))
        const href = safeHref(src.slice(close + 2, end))
        out.push(href ? { t: 'link', href, c: label } : { t: 'em', c: label })
        i = end + 1
        continue
      }
    }
    text += ch
    i++
  }
  flush()
  return out
}

/**
 * Parse block-level Markdown.
 * @param {string} md
 * @returns {Array<object>} blocks: {t:'h',level,c} | {t:'p',c} | {t:'ul'|'ol',items:[c]} | {t:'code',lang,v} | {t:'quote',c} | {t:'hr'}
 */
export function parse(md) {
  const lines = String(md || '').replace(/\r\n?/g, '\n').split('\n')
  const blocks = []
  let para = []
  const flushPara = () => { if (para.length) { blocks.push({ t: 'p', c: parseInline(para.join(' ')) }); para = [] } }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const fence = line.match(/^```\s*([\w-]*)\s*$/)
    if (fence) {
      flushPara()
      const body = []
      i++
      while (i < lines.length && !/^```\s*$/.test(lines[i])) body.push(lines[i++])
      blocks.push({ t: 'code', lang: fence[1] || '', v: body.join('\n') })
      continue
    }
    if (/^\s*$/.test(line)) { flushPara(); continue }
    const hd = line.match(/^(#{1,4})\s+(.*?)\s*#*\s*$/)
    if (hd) { flushPara(); blocks.push({ t: 'h', level: hd[1].length, c: parseInline(hd[2]) }); continue }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { flushPara(); blocks.push({ t: 'hr' }); continue }
    if (/^>\s?/.test(line)) {
      flushPara()
      const body = []
      while (i < lines.length && /^>\s?/.test(lines[i])) body.push(lines[i++].replace(/^>\s?/, ''))
      i--
      blocks.push({ t: 'quote', c: parseInline(body.join(' ')) })
      continue
    }
    const li = line.match(/^\s*([-*+]|\d+[.)])\s+(.*)$/)
    if (li) {
      flushPara()
      const ordered = /\d/.test(li[1])
      const items = []
      while (i < lines.length) {
        const m = lines[i].match(/^\s*([-*+]|\d+[.)])\s+(.*)$/)
        if (m && /\d/.test(m[1]) === ordered) { items.push(m[2]); i++; continue }
        if (items.length && /^\s{2,}\S/.test(lines[i])) { items[items.length - 1] += ' ' + lines[i].trim(); i++; continue }
        break
      }
      i--
      blocks.push({ t: ordered ? 'ol' : 'ul', items: items.map(parseInline) })
      continue
    }
    para.push(line.trim())
  }
  flushPara()
  return blocks
}

/** Slug for heading anchors. */
export const slug = (s) => String(s).toLowerCase().replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-')

const plain = (nodes) => nodes.map(n => (n.v !== undefined ? n.v : plain(n.c || []))).join('')

/**
 * Render Markdown to a DocumentFragment using safe DOM APIs.
 * @param {string} md
 * @param {{onLink?: (href:string, ev:MouseEvent) => void, headingOffset?: number}} [opts]
 *   onLink: called for root-relative links (e.g. /docs/devices) so the help panel can navigate in place.
 */
export function render(md, opts = {}) {
  const doc = globalThis.document
  const el = (tag, cls) => { const e = doc.createElement(tag); if (cls) e.className = cls; return e }
  const inline = (parent, nodes) => {
    for (const n of nodes) {
      if (n.t === 'text') parent.append(doc.createTextNode(n.v))
      else if (n.t === 'code') { const c = el('code'); c.textContent = n.v; parent.append(c) }
      else if (n.t === 'strong' || n.t === 'em') { const s = el(n.t); inline(s, n.c); parent.append(s) }
      else if (n.t === 'link') {
        const a = el('a')
        a.href = n.href
        if (/^https:/i.test(n.href)) { a.target = '_blank'; a.rel = 'noopener noreferrer' }
        else if (opts.onLink && n.href.startsWith('/')) a.addEventListener('click', (ev) => opts.onLink(n.href, ev))
        inline(a, n.c)
        parent.append(a)
      }
    }
  }
  const f = doc.createDocumentFragment()
  for (const b of parse(md)) {
    if (b.t === 'h') {
      const lvl = Math.min(6, b.level + (opts.headingOffset || 0))
      const e = el(`h${lvl}`, 'md-h')
      e.id = `md-${slug(plain(b.c))}`
      inline(e, b.c)
      f.append(e)
    } else if (b.t === 'p') { const e = el('p'); inline(e, b.c); f.append(e) }
    else if (b.t === 'ul' || b.t === 'ol') {
      const e = el(b.t)
      for (const it of b.items) { const li = el('li'); inline(li, it); e.append(li) }
      f.append(e)
    } else if (b.t === 'code') {
      const pre = el('pre', 'md-code'); const c = el('code'); c.textContent = b.v; pre.append(c); f.append(pre)
    } else if (b.t === 'quote') { const q = el('blockquote', 'md-quote'); inline(q, b.c); f.append(q) }
    else if (b.t === 'hr') f.append(el('hr'))
  }
  return f
}
