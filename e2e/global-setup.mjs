// Seeds the live bundle: an E2E group, an operator (op@example.com) in it, and
// one enrolled (offline) device in it, so list and detail journeys never depend
// on state left behind by an earlier run.
import { request } from '@playwright/test'
import { ADMIN, api, enrolDevice } from './fixtures.mjs'

export const SEED_DEVICE = 'e2e-seed-box'

export default async function () {
  const rq = await request.newContext({ ignoreHTTPSErrors: true })
  const groups = await api(rq, ADMIN, 'GET', '/api/v1/groups')
  let g = groups.body.data.find(x => x.name === 'E2E')
  if (!g) g = (await api(rq, ADMIN, 'POST', '/api/v1/groups', { name: 'E2E', color: 'violet' })).body.data
  const users = await api(rq, ADMIN, 'GET', '/api/v1/users?q=op@example.com')
  if (!users.body.data.length) await api(rq, ADMIN, 'POST', '/api/v1/users', { email: 'op@example.com', role: 'operator', group_ids: [g.id] })
  const devs = await api(rq, ADMIN, 'GET', `/api/v1/devices?q=${SEED_DEVICE}`)
  if (!devs.body.data.some(d => d.name === SEED_DEVICE)) await enrolDevice(rq, { name: SEED_DEVICE, groupId: g.id })
  await rq.dispose()
}
