/**
 * Formatting helpers (UX-6) — the one place dates, numbers, bytes and durations become text.
 * Pure functions; locale defaults to the browser's (`navigator.language`) and can be passed for tests.
 *
 *  relativeTime(iso, now?)  → "just now", "5 min ago", "in 3 min", "2 days ago"
 *  absoluteTime(iso)        → "20 Nov 2026, 14:05:09" (locale-formatted, local time zone)
 *  dateTimeTitle(iso)       → full ISO-ish tooltip text incl. time zone
 *  timeOfDay(iso)           → "21:41:43.019" local, for log lines
 *  bytes(n)                 → "0 B", "1.5 KB", "3.2 GB" (1024 base, IEC-style units without the i)
 *  duration(seconds)        → "45 s", "3 min 20 s", "2 h 5 min", "3 d 4 h"
 *  durationMs(ms)           → "12 ms", "1.2 s"
 *  number(n)                → locale grouping
 *  countdown(iso, now?)     → "14:59" mm:ss remaining (or "0:00")
 *  plural(n, one, many?)    → "1 device", "3 devices"
 *  csvCell(v)               → one CSV field, quoted, with spreadsheet formula-injection guard
 *  eventLabel('device.connect') → 'Device connect'
 *  shareDuration(60)        → '1 hour' (session share durations, SHARE_DURATIONS)
 *  shareModeLabel('control') → 'Control'
 */

const defaultLocale = () => (globalThis.navigator?.language || 'en-GB')

/** @param {string|number|Date|null|undefined} v */
export function toDate(v) {
  if (v === null || v === undefined || v === '') return null
  const d = v instanceof Date ? v : new Date(v)
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1971 ? null : d
}

const UNITS = [
  ['year', 365 * 24 * 3600], ['month', 30 * 24 * 3600], ['week', 7 * 24 * 3600],
  ['day', 24 * 3600], ['hour', 3600], ['minute', 60], ['second', 1],
]

/**
 * @param {string|Date|null} iso
 * @param {Date|number} [now]
 * @param {string} [locale]
 */
export function relativeTime(iso, now = Date.now(), locale = defaultLocale()) {
  const d = toDate(iso)
  if (!d) return 'never'
  const diff = Math.round((d.getTime() - Number(now)) / 1000)
  const abs = Math.abs(diff)
  if (abs < 45) return 'just now'
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto', style: 'short' })
  for (const [unit, secs] of UNITS) {
    if (abs >= secs || unit === 'second') return rtf.format(Math.round(diff / secs), unit)
  }
  return 'just now'
}

/** @param {string|Date|null} iso */
export function absoluteTime(iso, locale = defaultLocale()) {
  const d = toDate(iso)
  if (!d) return '—'
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(d)
}

/** Local wall-clock time with milliseconds for log lines: "21:41:43.019" (adds the date if not today). */
export function timeOfDay(iso, now = Date.now(), locale = defaultLocale()) {
  const d = toDate(iso)
  if (!d) return '—'
  const t = new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(d)
  const ms = String(d.getMilliseconds()).padStart(3, '0')
  const sameDay = new Date(Number(now)).toDateString() === d.toDateString()
  return sameDay ? `${t}.${ms}` : `${new Intl.DateTimeFormat(locale, { month: 'short', day: 'numeric' }).format(d)} ${t}.${ms}`
}

/** Tooltip text: absolute time with zone, so the relative label can always be verified. */
export function dateTimeTitle(iso, locale = defaultLocale()) {
  const d = toDate(iso)
  if (!d) return ''
  return new Intl.DateTimeFormat(locale, { dateStyle: 'full', timeStyle: 'long' }).format(d)
}

/** @param {number|null|undefined} n */
export function bytes(n) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '—'
  let v = Number(n)
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return i === 0 ? `${v} B` : `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')} ${units[i]}`
}

/** @param {number|null|undefined} seconds */
export function duration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return '—'
  let s = Math.max(0, Math.round(Number(seconds)))
  if (s < 60) return `${s} s`
  const d = Math.floor(s / 86400); s -= d * 86400
  const h = Math.floor(s / 3600); s -= h * 3600
  const m = Math.floor(s / 60); s -= m * 60
  if (d) return h ? `${d} d ${h} h` : `${d} d`
  if (h) return m ? `${h} h ${m} min` : `${h} h`
  return s ? `${m} min ${s} s` : `${m} min`
}

/** @param {number|null|undefined} ms */
export function durationMs(ms) {
  if (ms === null || ms === undefined || Number.isNaN(Number(ms))) return '—'
  const v = Number(ms)
  if (v < 1000) return `${Math.round(v)} ms`
  return v < 60000 ? `${(v / 1000).toFixed(1).replace(/\.0$/, '')} s` : duration(v / 1000)
}

/** Seconds between two timestamps (end defaults to now). */
export function between(startIso, endIso, now = Date.now()) {
  const a = toDate(startIso)
  if (!a) return null
  const b = toDate(endIso)
  return ((b ? b.getTime() : Number(now)) - a.getTime()) / 1000
}

/** @param {number|null|undefined} n */
export function number(n, locale = defaultLocale()) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '—'
  return new Intl.NumberFormat(locale).format(Number(n))
}

/** "mm:ss" (or "h:mm:ss") remaining until iso; "0:00" once passed. */
export function countdown(iso, now = Date.now()) {
  const d = toDate(iso)
  if (!d) return '—'
  let s = Math.max(0, Math.floor((d.getTime() - Number(now)) / 1000))
  const h = Math.floor(s / 3600); s -= h * 3600
  const m = Math.floor(s / 60); s -= m * 60
  const ss = String(s).padStart(2, '0')
  return h ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`
}

/** @param {number} n @param {string} one @param {string} [many] */
export function plural(n, one, many = `${one}s`) {
  return `${number(n)} ${Number(n) === 1 ? one : many}`
}

/** Human label for an OS id from the API. */
export function osLabel(os) {
  return { linux: 'Linux', macos: 'macOS', windows: 'Windows' }[os] || 'Unknown'
}

/**
 * Labels that tell devices apart in pickers and lists. A unique name is shown as it is. When
 * several devices share a name (one machine enrolled twice, or two machines named alike), the
 * label adds the hostname, then a short device ID if that still collides, then online/offline
 * when known — so a person can pick the right one.
 * @param {{id:string, name?:string, hostname?:string, online?:boolean}[]} devices  repeats of one id are fine
 * @returns {Map<string,string>} device id → label
 */
export function deviceLabels(devices) {
  const byId = new Map()
  for (const d of devices || []) if (d?.id && !byId.has(d.id)) byId.set(d.id, d)
  const tally = (key) => {
    const n = new Map()
    for (const d of byId.values()) n.set(key(d), (n.get(key(d)) || 0) + 1)
    return n
  }
  const names = tally(d => d.name || d.id)
  const hosts = tally(d => `${d.name || d.id}\u0000${d.hostname || ''}`)
  const out = new Map()
  for (const d of byId.values()) {
    const name = d.name || d.id
    if (names.get(name) < 2) { out.set(d.id, name); continue }
    const parts = [name]
    if (d.hostname && d.hostname !== name) parts.push(d.hostname)
    if (!d.hostname || hosts.get(`${name}\u0000${d.hostname}`) > 1) parts.push(String(d.id).replace(/^dev_/, '').slice(0, 6))
    if (typeof d.online === 'boolean') parts.push(d.online ? 'online' : 'offline')
    out.set(d.id, parts.join(' · '))
  }
  return out
}

/** Human label for a service kind. */
export function serviceLabel(kind) {
  return { ssh: 'SSH', rdp: 'RDP', vnc: 'VNC' }[kind] || String(kind || '').toUpperCase()
}

/** Default remote port for a service kind (matches the client protocol's detection). */
export const DEFAULT_PORTS = Object.freeze({ ssh: 22, rdp: 3389, vnc: 5900 })

/** CSV cell with quoting and a spreadsheet formula-injection guard (cells starting = + - @ get a ' prefix). */
export function csvCell(v) {
  let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join('; ') : typeof v === 'object' ? JSON.stringify(v) : String(v)
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** Human label for an audit/log event name: 'device.connect' → 'Device connect'. */
export const eventLabel = (e) => String(e || '').replace(/[._]/g, ' ').replace(/^\w/, c => c.toUpperCase())

/** Share durations offered when sharing a session, in minutes. */
export const SHARE_DURATIONS = Object.freeze([15, 30, 60, 120, 240, 480])

/** "15 minutes", "1 hour", "8 hours" — labels for share durations. */
export function shareDuration(min) {
  const m = Number(min)
  if (!Number.isFinite(m) || m <= 0) return '—'
  if (m < 60 || m % 60 !== 0) return `${m} ${m === 1 ? 'minute' : 'minutes'}`
  const h = m / 60
  return `${h} ${h === 1 ? 'hour' : 'hours'}`
}

/** Label for a share mode from the API. */
export function shareModeLabel(mode) {
  return mode === 'control' ? 'Control' : 'View only'
}
