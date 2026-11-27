// RemoteHound artwork: the beagle, adapted from MediaHound's hound (docs/BRAND.md).
// One set of shapes feeds every file, so they never drift. Run from the repo root:
//   node tools/brand/build.mjs
// Writes web/ui/brand/*, web/ui/favicon.svg, docs/img/logo-*.svg and the website/img copies.
import { writeFileSync } from 'node:fs'

const C = {
  coat: '#D9822B', ear: '#B5651D', white: '#FFFFFF', ink: '#16232A', tongue: '#F2654E',
  blue: '#24478A', blueDark: '#4A74BD', screen: '#EEF3FB', screenDark: '#15203A', tan: '#DDA45F', outline: '#F5F7FA',
}

// beagle head + ears, drawn on the 120-wide grid, centerd on x=60, chin at y≈101
function head({ simple = false } = {}) {
  const ear = 'M41 58C30 58 24 70 25 85C26 96 31 102 37 101C44 100 46 92 46 83C46 72 45 62 41 58Z'
  const earR = 'M79 58C90 58 96 70 95 85C94 96 89 102 83 101C76 100 74 92 74 83C74 72 75 62 79 58Z'
  const skull = 'M60 51C76 51 87 62 87 76C87 91 76 101 60 101C44 101 33 91 33 76C33 62 44 51 60 51Z'
  const blaze = 'M57 51.3C58.5 51 61.5 51 63 51.3L64.6 72C65 75 66 77 68 78.5L49 78.5C51 77 52.6 75 53 72Z'
  const muzzle = 'M60 76C70 76 76 81.5 76 88.5C76 95.5 69 100.6 60 100.6S44 95.5 44 88.5C44 81.5 50 76 60 76Z'
  const nose = 'M54.4 83.2C54.4 81.2 57 80.4 60 80.4S65.6 81.2 65.6 83.2C65.6 86.2 62.6 88.6 60 88.6S54.4 86.2 54.4 83.2Z'
  const r = simple ? 5.2 : 4.5
  let s = `<path fill="${C.coat}" d="${skull}"/>`
  s += `<path fill="${C.white}" d="${blaze}"/><path fill="${C.white}" d="${muzzle}"/>`
  s += `<path fill="${C.ear}" d="${ear}"/><path fill="${C.ear}" d="${earR}"/>`
  s += `<circle fill="${C.ink}" cx="49.5" cy="74" r="${r}"/><circle fill="${C.ink}" cx="70.5" cy="74" r="${r}"/>`
  if (!simple) {
    s += `<circle fill="${C.white}" cx="51" cy="72.4" r="1.6"/><circle fill="${C.white}" cx="72" cy="72.4" r="1.6"/>`
    s += `<path fill="none" stroke="${C.ink}" stroke-width="1.9" stroke-linecap="round" d="M44.8 65.6C46.8 63.6 50.2 63.2 52.8 64.6M67.2 64.6C69.8 63.2 73.2 63.6 75.2 65.6"/>`
  }
  s += `<path fill="${C.ink}" d="${nose}"/>`
  if (!simple) {
    s += `<path fill="${C.tongue}" d="M56.6 94.2C56.6 98.6 63.4 98.6 63.4 94.2Z"/>`
    s += `<path fill="none" stroke="${C.ink}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" d="M60 88.6V92.2M51.5 91C54 95.6 66 95.6 68.5 91"/>`
  } else {
    s += `<path fill="none" stroke="${C.ink}" stroke-width="2.4" stroke-linecap="round" d="M52 91.5C55 95.5 65 95.5 68 91.5"/>`
  }
  return s
}

// signal arcs (the "remote" part), centerd on (cx, cy), opening upward
function arcs(cx, cy, color, w = 3.2, radii = [7, 13]) {
  const a = radii.map(rr => {
    const dx = (rr * Math.SQRT1_2).toFixed(2), dy = (rr * Math.SQRT1_2).toFixed(2)
    return `M${(cx - dx).toFixed(2)} ${(cy - dy).toFixed(2)}A${rr} ${rr} 0 0 1 ${(cx + +dx).toFixed(2)} ${(cy - dy).toFixed(2)}`
  }).join('')
  return `<path fill="none" stroke="${color}" stroke-width="${w}" stroke-linecap="round" d="${a}"/><circle fill="${color}" cx="${cx}" cy="${cy}" r="${(w * 0.85).toFixed(2)}"/>`
}

// full mascot: the beagle looking out of a browser window, signal arcs above it
function mascot(dark) {
  const frame = dark ? C.blueDark : C.blue, screen = dark ? C.screenDark : C.screen
  let s = arcs(60, 22, C.tan, 3.4, [8, 15])
  s += `<rect fill="${frame}" x="6" y="30" width="108" height="92" rx="14"/>`
  s += `<rect fill="${screen}" x="12" y="44" width="96" height="72" rx="8"/>`
  s += `<circle fill="${C.tan}" cx="18" cy="37" r="2.4"/><circle fill="${screen}" fill-opacity=".55" cx="25.5" cy="37" r="2.4"/><circle fill="${screen}" fill-opacity=".55" cx="33" cy="37" r="2.4"/>`
  s += `<path fill="none" stroke="${C.tan}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" d="M94.5 34.2L97.3 37L94.5 39.8M99.4 39.8H103.2"/>`
  s += `<g transform="translate(-15 -14.2) scale(1.25)">${head()}</g>`
  return svg('0 0 120 128', 'RemoteHound mascot', s)
}
// mark: head with the signal arcs above it
function mark() {
  const s = arcs(32, 17.5, C.tan, 3, [6, 11.5]) + `<g transform="translate(-16 -18.2) scale(.8)">${head({ simple: true })}</g>`
  return svg('0 0 64 64', 'RemoteHound', s)
}
function favicon() {
  const h = head({ simple: true })
  const halo = `<g fill="${C.outline}" stroke="${C.outline}" stroke-width="7" stroke-linejoin="round"><path d="M41 58C30 58 24 70 25 85C26 96 31 102 37 101C44 100 46 92 46 83C46 72 45 62 41 58Z"/><path d="M79 58C90 58 96 70 95 85C94 96 89 102 83 101C76 100 74 92 74 83C74 72 75 62 79 58Z"/><path d="M60 51C76 51 87 62 87 76C87 91 76 101 60 101C44 101 33 91 33 76C33 62 44 51 60 51Z"/></g>`
  return svg('0 0 32 32', null, `<g transform="translate(-8.4 -14.8) scale(.4)">${halo}${h}</g>`)
}
function logo(dark) {
  const s = `<g transform="translate(4 4)">${mark().trim().replace(/^<svg[^>]*>|<\/svg>$/g, '').replace(/<title>.*?<\/title>/, '')}</g>` +
    `<text x="80" y="49" fill="${dark ? '#E8EDF6' : '#101624'}" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,Helvetica,Arial,sans-serif" font-size="34" font-weight="700" letter-spacing="-0.6">Remote<tspan fill="${dark ? '#E9A55A' : '#B5651D'}">Hound</tspan></text>`
  return svg('0 0 360 72', 'RemoteHound', s)
}
function svg(vb, label, body) {
  const a = label ? ` role="img" aria-label="${label}"` : ''
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}"${a}>${label ? '<title>RemoteHound</title>' : ''}${body}</svg>\n`
}
const files = {
  'web/ui/brand/mascot.svg': mascot(false), 'web/ui/brand/mascot-dark.svg': mascot(true),
  // the mark's colors read on both surfaces; the -dark file is kept so app.css's theme switch is unchanged
  'web/ui/brand/mark.svg': mark(), 'web/ui/brand/mark-dark.svg': mark(),
  'web/ui/favicon.svg': favicon(),
  'docs/img/logo-light.svg': logo(false), 'docs/img/logo-dark.svg': logo(true),
  'website/img/mascot.svg': mascot(false), 'website/img/mascot-dark.svg': mascot(true),
  'website/img/mark.svg': mark(), 'website/img/favicon.svg': favicon(),
}
for (const [path, body] of Object.entries(files)) writeFileSync(path, body)
process.stdout.write(`wrote ${Object.keys(files).length} files\n`)
