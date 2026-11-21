/**
 * Users (/users) — who can sign in, their role and the groups they can reach.
 * Data: GET/POST /api/v1/users, PATCH (If-Match) / DELETE /api/v1/users/{id}.
 * The UI blocks obvious self-lockout (changing your own role, disabling or deleting yourself);
 * the server enforces it (LAST_ADMIN, AUTH_FORBIDDEN).
 */
import { h, replace, append } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { session, can, groups, groupMap } from '../lib/session.js'
import { page, grid, button, iconButton, field, checkList, drawer, confirmDialog, toast, toastError, applyFieldErrors, formError, badge, groupPill, relTime, banner } from '../lib/ui.js'

const ROLES = [
  { value: 'admin', label: 'Admin' },
  { value: 'operator', label: 'Operator' },
  { value: 'viewer', label: 'Viewer' },
]
const ROLE_TONE = { admin: 'brand', operator: 'info', viewer: 'neutral' }

export default function render(ctx) {
  const writable = can('user.write')
  let gmap = new Map()
  const p = page({
    title: 'Users',
    subtitle: 'People who can sign in. Roles decide what they can do; groups decide which devices they see.',
    helpKey: 'users',
    actions: [button({ label: 'Add user', icon: 'domain.action.invite', variant: 'primary', permission: 'user.write', onClick: () => edit(null) })],
  })

  function edit(user) {
    const isNew = !user
    const self = user && user.id === session.me?.id
    const f = {
      email: field({ id: 'users.email', label: 'Email', type: 'email', value: user?.email || '', required: true, maxlength: 254, disabled: !isNew, autocomplete: 'off' }),
      display_name: field({ id: 'users.display_name', label: 'Display name', value: user?.display_name || '', maxlength: 128 }),
      role: field({ id: 'users.role', label: 'Role', type: 'select', value: user?.role || 'viewer', options: ROLES, disabled: self }),
      group_ids: checkList({ id: 'users.group_ids', label: 'Groups', value: user?.group_ids || [], emptyText: 'No groups yet. Create groups to limit which devices this user sees.' }),
      disabled: field({ id: 'users.disabled', label: 'Block sign-in', type: 'checkbox', value: !!user?.disabled, disabled: self }),
    }
    groups().then(list => f.group_ids.setOptions(list.map(g => ({ value: g.id, label: groupPill(g) })))).catch(() => f.group_ids.setError('Groups could not be loaded.'))
    const roleNote = h('p', { class: 'field__help' })
    const syncRole = () => { roleNote.textContent = f.role.get() === 'admin' ? 'Admins see every group; the group list is ignored.' : '' }
    f.role.input.addEventListener('change', syncRole)
    syncRole()
    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form', novalidate: true, id: 'user-form' },
      self ? banner('info', 'This is you', 'You cannot change your own role or block yourself — ask another admin.') : null,
      msg, f.email.el, f.display_name.el, f.role.el, roleNote, f.group_ids.el, f.disabled.el)
    const save = button({ label: isNew ? 'Add user' : 'Save user', icon: 'action.save', variant: 'primary', type: 'submit' })
    save.setAttribute('form', 'user-form')
    const d = drawer({ title: isNew ? 'Add a user' : `Edit ${user.display_name || user.email}`, content: form, footer: h('div', { class: 'btn-row' }, button({ label: 'Cancel', variant: 'ghost', onClick: () => d.close() }), save) })
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      const email = f.email.get().trim()
      if (isNew && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { f.email.setError('Enter the email address the person signs in with.'); f.email.input.focus(); return }
      const body = { display_name: f.display_name.get().trim(), group_ids: f.group_ids.get() }
      if (isNew) body.email = email
      if (!self) { body.role = f.role.get(); body.disabled = f.disabled.get() }
      save.disabled = true
      try {
        if (isNew) await api.post('/api/v1/users', body)
        else await api.patch(`/api/v1/users/${encodeURIComponent(user.id)}`, body, user.etag)
        d.close()
        toast(isNew ? `${email} added` : 'User saved', { tone: 'success', detail: isNew ? 'They can sign in with your identity provider now.' : '' })
        g.reload()
      } catch (err) {
        if (err.status === 412) replace(msg, banner('warning', 'Someone else changed this user', 'Close this panel and open the user again to see the latest version.'))
        else if (!applyFieldErrors(f, err)) replace(msg, formError(err))
      } finally { save.disabled = false }
    })
  }

  async function remove(user) {
    const ok = await confirmDialog({ title: `Delete ${user.display_name || user.email}?`, body: 'They are signed out and cannot sign in again unless you add them back. Their audit history is kept.', confirmLabel: 'Delete user', tone: 'danger' })
    if (!ok) return
    try {
      await api.del(`/api/v1/users/${encodeURIComponent(user.id)}`)
      toast('User deleted', { tone: 'success' })
      g.reload()
    } catch (err) { toastError(err) }
  }

  let timer = null
  const qInput = h('input', { type: 'search', class: 'input input--search input--sm', placeholder: 'Search name or email', 'aria-label': 'Search users', maxlength: 100,
    onInput: () => { clearTimeout(timer); timer = setTimeout(() => g.reload({ q: qInput.value.trim() }), 300) } })
  ctx.onCleanup(() => clearTimeout(timer))

  const g = grid({
    label: 'Users',
    helpScreen: 'users',
    emptyKey: 'users',
    exportName: 'users',
    searchable: false,
    toolbar: h('div', { class: 'grid__search' }, qInput),
    onClearFilters: () => { qInput.value = ''; g.reload({ q: '' }) },
    initialSort: { id: 'name', dir: 'asc' },
    onRowClick: writable ? edit : null,
    load: async ({ pageToken, query, signal }) => {
      gmap = await groupMap()
      return api.get('/api/v1/users', { ...query, page_size: 50, page_token: pageToken }, { signal })
    },
    columns: [
      { id: 'name', label: 'Name', primary: true, value: (u) => u.display_name || u.email, render: (u) => h('span', { class: 'cell-stack' }, h('span', { class: 'cell-title' }, u.display_name || u.email, u.id === session.me?.id ? h('span', { class: 'muted' }, ' (you)') : null), u.display_name ? h('span', { class: 'cell-sub' }, u.email) : null) },
      { id: 'role', label: 'Role', render: (u) => badge(u.role, ROLE_TONE[u.role] || 'neutral') },
      { id: 'groups', label: 'Groups', sortable: false, value: (u) => (u.group_ids || []).map(id => gmap.get(id)?.name || id).join(', '),
        render: (u) => (u.role === 'admin' ? h('span', { class: 'muted' }, 'All groups') : (u.group_ids || []).length ? h('span', { class: 'chips' }, u.group_ids.map(id => groupPill(gmap.get(id) || { name: id, color: 'slate' }))) : h('span', { class: 'muted' }, 'None')) },
      { id: 'disabled', label: 'Sign-in', value: (u) => (u.disabled ? 'blocked' : 'allowed'), render: (u) => (u.disabled ? badge('Blocked', 'danger') : badge('Allowed', 'success')) },
      { id: 'last_login_at', label: 'Last sign-in', render: (u) => relTime(u.last_login_at) },
      writable ? { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (u) => h('span', { class: 'btn-row btn-row--tight' },
        iconButton({ icon: 'action.edit', label: `Edit ${u.email}`, size: 'sm', onClick: () => edit(u) }),
        u.id === session.me?.id ? null : iconButton({ icon: 'action.delete', label: `Delete ${u.email}`, size: 'sm', onClick: () => remove(u) })) } : null,
    ].filter(Boolean),
  })
  append(p.body, g.el)
  return p.el
}
