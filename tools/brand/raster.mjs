// Bitmap icons for browsers that ignore SVG favicons (Safari: tabs, bookmarks, Favorites; iOS home screen).
// Renders the SVGs written by build.mjs with headless Chrome and packs favicon.ico itself, so there are
// still no npm dependencies. Run from the repo root after build.mjs; commit the outputs:
//   node tools/brand/raster.mjs [/path/to/chrome]
// Writes web/ui/{favicon.ico,apple-touch-icon.png} and the same two files in website/img/.
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const BG = '#EEF3FB' // build.mjs C.screen: the light panel the mascot sits on

function chrome() {
  const candidates = [process.argv[2], '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].filter(Boolean)
  const found = candidates.find((p) => existsSync(p))
  if (!found) throw new Error('no Chrome/Chromium found — pass its path: node tools/brand/raster.mjs /path/to/chrome')
  return found
}

// Render one SVG to an n×n PNG. `pad` is the margin on each side; `bg` null keeps transparency.
function render(browser, dir, svgPath, n, { pad = 0, bg = null } = {}) {
  const page = join(dir, `p${n}.html`), out = join(dir, `p${n}.png`)
  const inner = n - 2 * pad
  writeFileSync(page, `<!doctype html><style>html,body{margin:0;background:${bg ?? 'transparent'}}` +
    `img{display:block;width:${inner}px;height:${inner}px;margin:${pad}px}</style>` +
    `<img src="${pathToFileURL(svgPath)}">`)
  const args = ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=1',
    `--window-size=${n},${n}`, `--screenshot=${out}`, pathToFileURL(page).href]
  if (!bg) args.unshift('--default-background-color=00000000') // transparent canvas
  execFileSync(browser, args, { stdio: 'ignore' })
  const png = readFileSync(out)
  if (png.readUInt32BE(16) !== n || png.readUInt32BE(20) !== n) throw new Error(`render of ${svgPath} at ${n}px came out the wrong size`)
  return png
}

// ICO with PNG-encoded entries (supported by every current browser and OS).
function ico(pngs) {
  const head = Buffer.alloc(6 + 16 * pngs.length)
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(pngs.length, 4)
  let offset = head.length
  pngs.forEach(({ n, png }, i) => {
    const e = 6 + 16 * i
    head.writeUInt8(n >= 256 ? 0 : n, e); head.writeUInt8(n >= 256 ? 0 : n, e + 1)
    head.writeUInt16LE(1, e + 4); head.writeUInt16LE(32, e + 6)
    head.writeUInt32LE(png.length, e + 8); head.writeUInt32LE(offset, e + 12)
    offset += png.length
  })
  return Buffer.concat([head, ...pngs.map((p) => p.png)])
}

const browser = chrome()
const dir = mkdtempSync(join(tmpdir(), 'rh-raster-'))
try {
  const fav = ico([16, 32, 48].map((n) => ({ n, png: render(browser, dir, 'web/ui/favicon.svg', n) })))
  // Apple touch icon: opaque (iOS fills transparency with black) and padded (iOS rounds the corners).
  const touch = render(browser, dir, 'web/ui/brand/mark.svg', 180, { pad: 18, bg: BG })
  const files = {
    'web/ui/favicon.ico': fav, 'web/ui/apple-touch-icon.png': touch,
    'website/img/favicon.ico': fav, 'website/img/apple-touch-icon.png': touch,
  }
  for (const [path, body] of Object.entries(files)) writeFileSync(path, body)
  process.stdout.write(`wrote ${Object.keys(files).length} files\n`)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
