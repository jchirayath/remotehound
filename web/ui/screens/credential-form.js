/**
 * "My saved login" form (personal credentials) — used by Profile and by the device page's
 * "Use my own login" affordance. Not a route.
 *
 * Data: GET /api/v1/devices (devices the user can see; only those with services are offered),
 * PUT /api/v1/me/credentials/{device_id}/{service} {username, password, private_key?} (write-only — the API
 * never returns either), DELETE same path. SSH logins may be a private key; the password box then holds
 * the key's passphrase (optional).
 */
import { h, replace } from '../lib/dom.js'
import { api } from '../lib/api.js'
import { drawer, field, button, toast, toastError, applyFieldErrors, formError, banner, confirmDialog } from '../lib/ui.js'
import { serviceLabel, deviceLabels } from '../lib/format.js'

const credPath = (deviceId, service) => `/api/v1/me/credentials/${encodeURIComponent(deviceId)}/${encodeURIComponent(service)}`

/**
 * @param {{deviceId?:string, service?:string, existing?:{device_id:string, device_name?:string, service:string, username?:string},
 *          onSaved?:() => void, intro?:{title:string, body:string}}} o  deviceId/service prefill and lock the picker
 *          (device page, edit); intro: why the login is needed (shown above the form)
 */
export function openCredentialForm(o = {}) {
  const locked = !!(o.existing || o.deviceId)
  const f = {
    // Editing an existing login: select its device (the only option). Without a value the
    // locked select shows blank and Save stops at "Choose the device…".
    device_id: field({ id: 'profile.credential_device', label: 'Device', type: 'select', required: true, disabled: locked,
      value: o.existing?.device_id,
      options: o.existing ? [{ value: o.existing.device_id, label: o.existing.device_name || o.existing.device_id }] : [{ value: '', label: 'Loading devices…' }] }),
    service: field({ id: 'profile.credential_service', label: 'Service', type: 'select', required: true, disabled: !!o.existing, options: [] }),
    username: field({ id: 'profile.credential_username', label: 'Username', value: o.existing?.username || '', maxlength: 128, autocomplete: 'off' }),
    password: field({ id: 'profile.credential_password', label: 'Password', type: 'password', maxlength: 512,
      placeholder: o.existing ? 'Type it again to save changes' : '' }),
    private_key: field({ id: 'profile.credential_private_key', label: 'Private key (SSH, optional)', type: 'textarea', rows: 4, mono: true,
      maxlength: 16384, placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' }),
  }
  // The key box only exists for SSH; with a key, the password box is the key's passphrase.
  const syncKind = () => {
    const ssh = f.service.get() === 'ssh'
    f.private_key.el.hidden = !ssh
    if (!ssh) f.private_key.set('')
    const label = f.password.el.querySelector('label')
    if (label) label.firstChild.textContent = ssh && f.private_key.get().trim() ? 'Key passphrase (if any)' : 'Password'
  }
  let devices = []
  const servicesFor = (id) => (devices.find(d => d.id === id)?.services || []).map(s => s.kind)
  const fillServices = (kinds) => {
    replace(f.service.input, kinds.length ? kinds.map(k => h('option', { value: k }, serviceLabel(k))) : h('option', { value: '' }, 'No services on this device'))
    if (o.service && kinds.includes(o.service)) f.service.set(o.service)
    else if (o.existing) f.service.set(o.existing.service)
    syncKind?.()
  }
  if (o.existing) fillServices([o.existing.service])
  f.service.input.addEventListener('change', syncKind)
  f.private_key.input.addEventListener('input', syncKind)
  syncKind()

  const msg = h('div', { class: 'form__msg' })
  const form = h('form', { class: 'form', novalidate: true, id: 'cred-form' },
    o.intro ? banner('warning', o.intro.title, o.intro.body) : null,
    banner('info', 'Only you can use this login', 'Connect uses your own login, so you get your own session. Nobody — admins included — can read the password or key.'),
    msg, f.device_id.el, f.service.el, f.username.el, f.password.el, f.private_key.el)
  const save = button({ label: 'Save login', icon: 'action.save', variant: 'primary', type: 'submit' })
  save.setAttribute('form', 'cred-form')
  const remove = o.existing ? button({ label: 'Delete', icon: 'action.delete', variant: 'ghost', onClick: async () => {
    if (!(await confirmDialog({ title: 'Delete this saved login?', body: 'You will be asked for a password when you connect, or a shared device login is used if one exists.', confirmLabel: 'Delete', tone: 'danger' }))) return
    try { await api.del(credPath(o.existing.device_id, o.existing.service)); toast('Saved login deleted', { tone: 'success' }); d.close(); o.onSaved?.() } catch (err) { toastError(err) }
  } }) : null
  const d = drawer({
    title: o.existing ? `Edit my login · ${o.existing.device_name || o.existing.device_id}` : 'Save my own login',
    content: form,
    footer: h('div', { class: 'btn-row' }, remove, button({ label: 'Cancel', variant: 'ghost', onClick: () => d.close() }), save),
  })

  if (!o.existing) {
    api.get('/api/v1/devices', { page_size: 200, order_by: 'name' }).then(r => {
      devices = (r.data || []).filter(dv => (dv.services || []).length)
      const labels = deviceLabels(devices)
      replace(f.device_id.input, devices.length
        ? [h('option', { value: '' }, 'Choose a device'), devices.map(dv => h('option', { value: dv.id }, labels.get(dv.id)))]
        : h('option', { value: '' }, 'No devices with services'))
      if (o.deviceId) f.device_id.set(o.deviceId)
      fillServices(servicesFor(f.device_id.get()))
    }).catch(err => replace(msg, formError(err)))
    f.device_id.input.addEventListener('change', () => fillServices(servicesFor(f.device_id.get())))
  }
  ;(o.existing ? f.password : f.device_id).input.focus()

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault()
    replace(msg)
    for (const x of Object.values(f)) x.setError('')
    const deviceId = f.device_id.get(), service = f.service.get(), password = f.password.get()
    const privateKey = service === 'ssh' ? f.private_key.get().trim() : ''
    if (!deviceId) { f.device_id.setError('Choose the device this login is for.'); f.device_id.input.focus(); return }
    if (!service) { f.service.setError('This device has no services yet; add one on its Services tab first.'); return }
    if (!password && !privateKey) { f.password.setError(service === 'ssh' ? 'Enter the password, or paste a private key below.' : 'Enter the password. It is stored encrypted and never shown again.'); f.password.input.focus(); return }
    save.disabled = true
    try {
      await api.put(credPath(deviceId, service), privateKey ? { username: f.username.get().trim(), password, private_key: privateKey } : { username: f.username.get().trim(), password })
      f.password.set('')
      f.private_key.set('')
      d.close()
      toast('Login saved', { tone: 'success', detail: 'Connect now uses your own login for this service.' })
      o.onSaved?.()
    } catch (err) {
      if (!applyFieldErrors(f, err)) replace(msg, formError(err))
    } finally { save.disabled = false }
  })
}
