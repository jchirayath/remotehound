/**
 * Groups (/groups) — organize devices and scope what operators and viewers can reach.
 * Data: GET/POST /api/v1/groups, PATCH (If-Match) / DELETE /api/v1/groups/{id}.
 * Colors are the domain group tokens (color.domain.group.*), picked from swatches — never free text.
 */
import { h, replace, uid, append } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { can, invalidateGroups } from '../lib/session.js'
import { fieldHelp } from '../lib/help.js'
import { page, grid, button, iconButton, field, drawer, confirmDialog, toast, toastError, applyFieldErrors, formError, groupPill, relTime, banner } from '../lib/ui.js'
import { number } from '../lib/format.js'

export const GROUP_COLORS = ['teal', 'violet', 'amber', 'rose', 'sky', 'lime', 'slate', 'orange']

/** Accessible swatch radio group. */
function colorPicker(value) {
  const name = uid('color')
  const helpId = uid('color-help')
  let current = GROUP_COLORS.includes(value) ? value : 'teal'
  const el = h('fieldset', { class: 'field swatches', 'aria-describedby': helpId },
    h('legend', { class: 'field__label' }, 'Color'),
    h('div', { class: 'swatches__row' }, GROUP_COLORS.map(c => {
      const id = uid('sw')
      const input = h('input', { type: 'radio', name, id, value: c, checked: c === current, class: 'swatch__input' })
      input.addEventListener('change', () => { current = c })
      return h('span', { class: 'swatch' }, input, h('label', { for: id, class: `swatch__label pill--${c}`, title: c }, h('span', { class: 'pill__swatch' }), h('span', { class: 'swatch__name' }, c)))
    })),
    h('p', { class: 'field__help', id: helpId }, fieldHelp('groups.color')))
  return { el, get: () => current, setError() {}, input: el.querySelector('input'), key: 'color' }
}

export default function render(ctx) {
  const writable = can('group.write')
  const p = page({
    title: 'Groups',
    subtitle: 'Groups organize devices and decide which devices operators and viewers can see.',
    helpKey: 'groups',
    actions: [button({ label: 'New group', icon: 'action.add', variant: 'primary', permission: 'group.write', onClick: () => edit(null) })],
  })

  function edit(group) {
    const isNew = !group
    const f = {
      name: field({ id: 'groups.name', label: 'Name', value: group?.name || '', required: true, maxlength: 64 }),
      description: field({ id: 'groups.description', label: 'Description', type: 'textarea', value: group?.description || '', maxlength: 500, rows: 3 }),
      color: colorPicker(group?.color),
    }
    const msg = h('div', { class: 'form__msg' })
    const form = h('form', { class: 'form', novalidate: true, id: 'group-form' }, msg, f.name.el, f.description.el, f.color.el)
    const save = button({ label: isNew ? 'Create group' : 'Save group', icon: 'action.save', variant: 'primary', type: 'submit' })
    save.setAttribute('form', 'group-form')
    const d = drawer({ title: isNew ? 'New group' : `Edit ${group.name}`, content: form, footer: h('div', { class: 'btn-row' }, button({ label: 'Cancel', variant: 'ghost', onClick: () => d.close() }), save) })
    f.name.input.focus()
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      replace(msg)
      const body = { name: f.name.get().trim(), description: f.description.get().trim(), color: f.color.get() }
      if (!body.name) { f.name.setError('Enter a name (up to 64 characters).'); f.name.input.focus(); return }
      save.disabled = true
      try {
        if (isNew) await api.post('/api/v1/groups', body)
        else await api.patch(`/api/v1/groups/${encodeURIComponent(group.id)}`, body, group.etag)
        invalidateGroups()
        d.close()
        toast(isNew ? `Group ${body.name} created` : `Group ${body.name} saved`, { tone: 'success' })
        g.reload()
      } catch (err) {
        if (err.status === 412) replace(msg, banner('warning', 'Someone else changed this group', 'Close this panel and open the group again to see the latest version.'))
        else if (!applyFieldErrors(f, err)) replace(msg, formError(err))
      } finally { save.disabled = false }
    })
  }

  async function remove(group) {
    const ok = await confirmDialog({
      title: `Delete ${group.name}?`,
      body: group.device_count ? `It still has ${number(group.device_count)} devices. Move them to another group first.` : 'Users scoped to this group lose access to it.',
      confirmLabel: 'Delete group', tone: 'danger',
    })
    if (!ok) return
    try {
      await api.del(`/api/v1/groups/${encodeURIComponent(group.id)}`)
      invalidateGroups()
      toast(`Group ${group.name} deleted`, { tone: 'success' })
      g.reload()
    } catch (err) { toastError(err) }
  }

  const g = grid({
    label: 'Groups',
    helpScreen: 'groups',
    emptyKey: 'groups',
    exportName: 'groups',
    initialSort: { id: 'name', dir: 'asc' },
    onRowClick: writable ? edit : null,
    load: ({ pageToken, signal }) => api.get('/api/v1/groups', { page_size: 100, page_token: pageToken }, { signal }),
    columns: [
      { id: 'name', label: 'Name', primary: true, render: (gr) => groupPill(gr) },
      { id: 'description', label: 'Description' },
      { id: 'device_count', label: 'Devices', align: 'end', render: (gr) => h('a', { href: `/devices?group_id=${encodeURIComponent(gr.id)}`, class: 'link' }, number(gr.device_count || 0)) },
      { id: 'updated_at', label: 'Updated', render: (gr) => relTime(gr.updated_at) },
      writable ? { id: 'actions', label: 'Actions', sortable: false, exportable: false, help: false, render: (gr) => h('span', { class: 'btn-row btn-row--tight' },
        iconButton({ icon: 'action.edit', label: `Edit ${gr.name}`, size: 'sm', onClick: () => edit(gr) }),
        iconButton({ icon: 'action.delete', label: `Delete ${gr.name}`, size: 'sm', onClick: () => remove(gr) })) } : null,
    ].filter(Boolean),
  })
  append(p.body, g.el)
  return p.el
}
