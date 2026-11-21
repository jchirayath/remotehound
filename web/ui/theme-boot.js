/*
 * Theme boot (THEME-6): loaded synchronously in <head> so the cached theme is applied before the
 * first paint. Classic script on purpose (not a module): modules are deferred and would flash.
 * Reads only the display preference 'rh.theme' (system|light|dark); lib/theme.js owns changes.
 */
(function () {
  try {
    var m = localStorage.getItem('rh.theme')
    if (m === 'light' || m === 'dark') document.documentElement.setAttribute('data-theme', m)
    if (localStorage.getItem('rh.sidebar') === 'collapsed') document.documentElement.classList.add('sidebar-collapsed')
  } catch (e) {
    // storage blocked (private mode): follow the OS theme
    document.documentElement.removeAttribute('data-theme')
  }
})()
