/**
 * Signed-in user state and small shared caches.
 *
 * Contract
 *  - `session.me` is the Me object from GET /api/v1/me (set once at boot by app.js).
 *  - `can(action)` → boolean for UI gating only (hide/disable). The server re-checks every call.
 *  - `groups()` → cached Promise<Group[]> (all pages) used by pickers and pills; `invalidateGroups()`
 *    after any group change.
 */
import { api } from './api.js'

export const session = {
  /** @type {null | {id:string,email:string,display_name:string,role:string,permissions:string[],group_ids:string[],csrf_token:string,theme:string,auth_mode:string,version:string}} */
  me: null,
}

/** @param {string} action e.g. 'device.connect' */
export function can(action) {
  return !!session.me?.permissions?.includes(action)
}

let groupsPromise = null

/** Load every group (follows cursor pages; groups are few). */
export function groups() {
  if (!can('group.read')) return Promise.resolve([])
  if (!groupsPromise) {
    groupsPromise = (async () => {
      const all = []
      let token = ''
      for (let i = 0; i < 20; i++) {
        const r = await api.get('/api/v1/groups', { page_size: 200, page_token: token })
        all.push(...(r.data || []))
        token = r.meta?.next_page_token || ''
        if (!token) break
      }
      return all.sort((a, b) => a.name.localeCompare(b.name))
    })().catch((e) => { groupsPromise = null; throw e })
  }
  return groupsPromise
}

export function invalidateGroups() { groupsPromise = null }

/** Map group id → group (from the cache). */
export async function groupMap() {
  try {
    return new Map((await groups()).map(g => [g.id, g]))
  } catch {
    return new Map()
  }
}
