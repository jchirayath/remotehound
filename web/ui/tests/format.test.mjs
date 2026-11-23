// Unit tests for lib/format.js (UX-6). Run: node --test web/ui/tests/
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SHARE_DURATIONS, shareDuration, shareModeLabel, timeOfDay, relativeTime, bytes, duration, durationMs, countdown, plural, toDate, between, csvCell, eventLabel, osLabel, serviceLabel, deviceLabels } from '../lib/format.js'

const NOW = Date.parse('2026-11-20T12:00:00Z')

test('@feature:devices relativeTime describes last-seen times', () => {
  assert.equal(relativeTime('2026-11-20T11:59:50Z', NOW, 'en'), 'just now')
  assert.match(relativeTime('2026-11-20T11:55:00Z', NOW, 'en'), /5 min/)
  assert.match(relativeTime('2026-11-18T12:00:00Z', NOW, 'en'), /2 days ago/)
  assert.match(relativeTime('2026-11-20T12:10:00Z', NOW, 'en'), /in 10 min/)
  assert.equal(relativeTime(null, NOW, 'en'), 'never')
  assert.equal(relativeTime('0001-01-01T00:00:00Z', NOW, 'en'), 'never', 'Go zero time is treated as never')
})

test('@feature:sessions @feature:debug bytes uses binary units', () => {
  assert.equal(bytes(0), '0 B')
  assert.equal(bytes(1023), '1023 B')
  assert.equal(bytes(1536), '1.5 KB')
  assert.equal(bytes(1024 * 1024 * 300), '300 MB')
  assert.equal(bytes(null), '—')
})

test('@feature:sessions duration and between', () => {
  assert.equal(duration(42), '42 s')
  assert.equal(duration(200), '3 min 20 s')
  assert.equal(duration(3600 * 2 + 300), '2 h 5 min')
  assert.equal(duration(86400 * 3 + 3600 * 4), '3 d 4 h')
  assert.equal(duration(undefined), '—')
  assert.equal(between('2026-11-20T11:00:00Z', '2026-11-20T11:30:00Z'), 1800)
  assert.equal(between('2026-11-20T11:59:00Z', null, NOW), 60)
})

test('@feature:integration durationMs for check latency', () => {
  assert.equal(durationMs(12), '12 ms')
  assert.equal(durationMs(1200), '1.2 s')
  assert.equal(durationMs(2000), '2 s')
})

test('@feature:enroll countdown to code expiry', () => {
  assert.equal(countdown('2026-11-20T12:14:59Z', NOW), '14:59')
  assert.equal(countdown('2026-11-20T13:00:05Z', NOW), '1:00:05')
  assert.equal(countdown('2026-11-20T11:00:00Z', NOW), '0:00')
})

test('@feature:overview plural and event labels', () => {
  assert.equal(plural(1, 'device'), '1 device')
  assert.match(plural(3, 'device'), /^3 devices$/)
  assert.equal(eventLabel('device.connect'), 'Device connect')
  assert.equal(eventLabel('enrollment_create'), 'Enrollment create')
})

test('@feature:audit csvCell quotes and guards against formula injection', () => {
  assert.equal(csvCell('plain'), 'plain')
  assert.equal(csvCell('a,b'), '"a,b"')
  assert.equal(csvCell('say "hi"'), '"say ""hi"""')
  assert.equal(csvCell('=HYPERLINK("x")'), `"'=HYPERLINK(""x"")"`)
  assert.equal(csvCell('+1'), "'+1")
  assert.equal(csvCell(['a', 'b']), 'a; b')
  assert.equal(csvCell(null), '')
})

test('@feature:devices labels for OS and services', () => {
  assert.equal(osLabel('macos'), 'macOS')
  assert.equal(osLabel('beos'), 'Unknown')
  assert.equal(serviceLabel('rdp'), 'RDP')
  assert.equal(toDate('not a date'), null)
})

test('@feature:logs timeOfDay shows local time with milliseconds', () => {
  const d = new Date(NOW - 1000)
  d.setMilliseconds(19)
  assert.match(timeOfDay(d.toISOString(), d.getTime(), 'en-GB'), /^\d{2}:\d{2}:\d{2}\.019$/)
  assert.match(timeOfDay('2026-01-02T03:04:05.006Z', NOW, 'en-GB'), /Jan .*\.006$/)
})

test('@feature:sessions share durations and modes', () => {
  assert.deepEqual([...SHARE_DURATIONS], [15, 30, 60, 120, 240, 480])
  assert.deepEqual(SHARE_DURATIONS.map(shareDuration), ['15 minutes', '30 minutes', '1 hour', '2 hours', '4 hours', '8 hours'])
  assert.equal(shareDuration(90), '90 minutes')
  assert.equal(shareDuration(0), '—')
  assert.equal(shareModeLabel('control'), 'Control')
  assert.equal(shareModeLabel('view'), 'View only')
  assert.equal(shareModeLabel(undefined), 'View only', 'unknown modes never claim control')
})

test('@feature:devices @feature:help deviceLabels tells devices with the same name apart', () => {
  const labels = deviceLabels([
    { id: 'dev_unique1', name: 'kiosk', hostname: 'kiosk', online: true },
    { id: 'dev_aaaaaa11', name: 'live-box', hostname: 'host-a', online: true },
    { id: 'dev_bbbbbb22', name: 'live-box', hostname: 'host-b', online: false },
    { id: 'dev_cccccc33', name: 'twin', hostname: 'same', online: false },
    { id: 'dev_dddddd44', name: 'twin', hostname: 'same', online: true },
    { id: 'dev_eeeeee55', name: 'nohost' },
    { id: 'dev_ffffff66', name: 'nohost' },
  ])
  assert.equal(labels.get('dev_unique1'), 'kiosk', 'a unique name stays exactly as it is')
  assert.equal(labels.get('dev_aaaaaa11'), 'live-box · host-a · online')
  assert.equal(labels.get('dev_bbbbbb22'), 'live-box · host-b · offline')
  assert.equal(labels.get('dev_cccccc33'), 'twin · same · cccccc · offline', 'same hostname too: the short ID decides')
  assert.equal(labels.get('dev_dddddd44'), 'twin · same · dddddd · online')
  assert.equal(labels.get('dev_eeeeee55'), 'nohost · eeeeee', 'unknown presence is not claimed')
  assert.notEqual(labels.get('dev_eeeeee55'), labels.get('dev_ffffff66'))
  // Two rows for one device (e.g. its SSH and RDP logins) are not a collision.
  const one = deviceLabels([{ id: 'dev_x', name: 'pc' }, { id: 'dev_x', name: 'pc' }])
  assert.equal(one.get('dev_x'), 'pc')
  assert.equal(deviceLabels([]).size, 0)
})
