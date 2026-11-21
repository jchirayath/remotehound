/**
 * The route table — pure data, shared by app.js (router + navigation) and the tests that check
 * every route has a help-registry entry and a user doc (HELP-7).
 *
 * Fields: path (router pattern), help (registry screen key), label, icon (registry name),
 * section (sidebar group; omitted = not in navigation), perm (permission needed), screen (module in
 * ./screens/), parent (highlighted nav item for nested routes), public (renders without a session —
 * the sign-in page), palette (reachable from the command palette and More menu without a sidebar entry).
 */
export const ROUTES = [
  { path: '/login', help: 'login', label: 'Sign in', icon: 'action.logout', screen: 'login', public: true },
  { path: '/signed-out', help: 'login', label: 'Signed out', icon: 'action.logout', screen: 'noaccess', public: true },
  { path: '/profile', help: 'profile', label: 'Profile', icon: 'nav.profile', screen: 'profile', palette: true },
  { path: '/', help: 'overview', label: 'Overview', icon: 'domain.nav.overview', section: 'Operate', screen: 'overview' },
  { path: '/devices', help: 'devices', label: 'Devices', icon: 'domain.nav.devices', section: 'Operate', perm: 'device.read', screen: 'devices' },
  { path: '/devices/:id', help: 'device', label: 'Device', icon: 'domain.nav.devices', perm: 'device.read', screen: 'device-detail', parent: '/devices' },
  { path: '/enroll', help: 'enroll', label: 'Enroll', icon: 'domain.nav.enroll', section: 'Operate', perm: 'enrollment.read', screen: 'enroll' },
  { path: '/sessions', help: 'sessions', label: 'Sessions', icon: 'domain.nav.sessions', section: 'Operate', perm: 'session.read', screen: 'sessions' },
  { path: '/groups', help: 'groups', label: 'Groups', icon: 'domain.nav.groups', section: 'Organise', perm: 'group.read', screen: 'groups' },
  { path: '/users', help: 'users', label: 'Users', icon: 'object.users', section: 'Organise', perm: 'user.read', screen: 'users' },
  { path: '/services', help: 'services', label: 'Services', icon: 'domain.nav.services', section: 'Observe', perm: 'services.read', screen: 'services' },
  { path: '/integration', help: 'integration', label: 'Integration', icon: 'domain.nav.integration', section: 'Observe', perm: 'integration.read', screen: 'integration' },
  { path: '/logs', help: 'logs', label: 'Logs', icon: 'domain.nav.logs', section: 'Observe', perm: 'logs.read', screen: 'logs' },
  { path: '/audit', help: 'audit', label: 'Audit', icon: 'domain.nav.audit', section: 'Observe', perm: 'audit.read', screen: 'audit' },
  { path: '/debug', help: 'debug', label: 'Debug', icon: 'domain.nav.debug', section: 'Observe', perm: 'debug.read', screen: 'debug' },
  { path: '/settings', help: 'settings', label: 'Settings', icon: 'action.settings', section: 'Configure', perm: 'settings.read', screen: 'settings' },
]
export const NOT_FOUND = { path: '*', help: 'notfound', label: 'Not found', screen: 'notfound' }
export const TABBAR = ['/', '/devices', '/enroll', '/sessions']
