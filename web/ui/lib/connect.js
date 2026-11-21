/**
 * Opening a Guacamole session tab — shared by Connect (device page) and Join (sessions screen).
 *
 * Contract: `openSession(request, {what})`
 *  - `request` is a function returning the API promise (POST …/connect or …/join) whose data has `url`.
 *  - On wide screens a blank tab is opened synchronously inside the click (so popup blockers allow
 *    it) and pointed at the URL once it arrives; on phones (<600px) the current tab navigates.
 *  - The URL must be a same-origin relative path (router.isSessionUrl) or it is refused.
 *  - Failures close the blank tab and show the registry fix for the error code (HELP-3).
 * @param {() => Promise<{data:{url:string}}>} request
 * @param {{what:string, button?:HTMLElement, onError?:(err:any) => boolean}} o  what: human label for the toast, e.g.
 *        "RDP to laptop1"; onError: return true when it handled the failure (no error toast)
 * @returns {Promise<boolean>} whether a session was opened
 */
import { isSessionUrl } from './router.js'
import { toast, toastError } from './ui.js'

export async function openSession(request, o) {
  const compact = matchMedia('(max-width: 599px)').matches
  const win = compact ? null : globalThis.open('', '_blank')
  if (win) { win.opener = null; win.document.title = 'Connecting…' }
  o.button?.setAttribute('aria-busy', 'true')
  try {
    const r = await request()
    const url = r.data?.url
    if (!isSessionUrl(url)) throw Object.assign(new Error('bad session url'), { code: 'GUAC_UNAVAILABLE', title: 'The server returned no usable session link' })
    if (win) win.location.href = url
    else globalThis.location.assign(url)
    toast(`Opening ${o.what}`, { tone: 'success', detail: 'The link is valid for a short time; select the button again if it expires.' })
    return true
  } catch (err) {
    win?.close()
    if (!o.onError?.(err)) toastError(err, 'Could not open the session')
    return false
  } finally {
    o.button?.removeAttribute('aria-busy')
  }
}
