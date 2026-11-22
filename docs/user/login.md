# Signing in

RemoteHound has no passwords of its own. You sign in with an account your organisation already uses — for example Microsoft Entra ID, Google, Apple, Facebook, GitHub or another OpenID Connect provider. RemoteHound never sees your provider password.

## Choosing a sign-in method

When more than one method is enabled, the sign-in page shows one button per provider. Select the one for the account you use at work. After signing in at the provider you return to the page you were trying to open.

When only one method is enabled, RemoteHound sends you straight to it. Organisations that put RemoteHound behind their own sign-in proxy skip this page entirely.

## What is recorded

Every sign-in, and everything you do while signed in, is recorded in the [audit log](/docs/audit) with your name, role and IP address.

## Signing out

**Sign out** ends your RemoteHound session everywhere and also closes any remote desktop or terminal tabs you have open: their Guacamole sessions are revoked and the browser forgets Guacamole's saved sign-in. Behind a sign-in proxy you are then sent to the proxy's own sign-out page.

## Linking more than one method

You can link several providers to the same RemoteHound account on your [Profile](/docs/profile), so you can still sign in if one provider is unavailable.

## Troubleshooting

- **"Your account is not set up in RemoteHound."** You signed in at the provider, but no RemoteHound user matches your account. Ask an admin to add your email on the [Users](/docs/users) screen.
- **The provider says the app is not allowed.** Your administrator must allow RemoteHound in that provider. Try another method or contact them.
- **The first admin cannot get in.** The bootstrap admin must sign in with a verified email address at the provider; unverified emails are refused.
