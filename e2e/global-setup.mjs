// Seeds the live bundle: an E2E group and an operator (op@example.com) in it.
import { request } from '@playwright/test'
import { ADMIN, api } from './fixtures.mjs'

export default async function () {
  const rq = await request.newContext({ ignoreHTTPSErrors: true })
  const groups = await api(rq, ADMIN, 'GET', '/api/v1/groups')
  let g = groups.body.data.find(x => x.name === 'E2E')
  if (!g) g = (await api(rq, ADMIN, 'POST', '/api/v1/groups', { name: 'E2E', color: 'violet' })).body.data
  const users = await api(rq, ADMIN, 'GET', '/api/v1/users?q=op@example.com')
  if (!users.body.data.length) await api(rq, ADMIN, 'POST', '/api/v1/users', { email: 'op@example.com', role: 'operator', group_ids: [g.id] })
  await rq.dispose()
}
