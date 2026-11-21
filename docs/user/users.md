# Users

The Users screen controls who can sign in, what they can do and which devices they can see. RemoteHound has no passwords of its own: people sign in through your identity provider (for example Microsoft Entra ID, Google or Keycloak), and multi-factor authentication is handled there.

## Add a user

1. Select **Add user**.
2. Type the **Email** the person signs in with. The user is linked to their identity provider account the first time they sign in.
3. Choose a **Role**:
   - **Admin**: full control, including users, settings, logs and debugging.
   - **Operator**: connect to and manage devices, and enrol new ones, in their groups.
   - **Viewer**: read-only access to devices and sessions in their groups.
4. Tick the **Groups** whose devices they can see. Admins see all groups, so the list is ignored for them.
5. Select **Add user**.

## Block or remove someone

- **Block sign-in** suspends a user immediately and ends their sessions, but keeps them in the list and in the audit log.
- **Delete** removes the user. Their audit history is kept.

## Safety rules

- You cannot change your own role, block yourself or delete yourself.
- The last admin cannot be demoted or deleted. Make someone else an admin first.

## Sign-in methods

Each person can link several sign-in methods (for example Microsoft Entra and GitHub) to one account from their [Profile](/docs/profile). They can unlink any method except the last one. When several providers are enabled, people choose one on the [sign-in page](/docs/login).

The first (bootstrap) admin must sign in with an email address the provider has verified; unverified emails are refused, so nobody can claim the admin account by typing its address.

## Roles from your identity provider

Instead of setting roles by hand, you can map a claim from your identity provider (such as group membership) to roles under **Settings → Sign-in roles** (the role map: claim value on the left, role on the right; the highest match wins). Removing a row stops granting that role at the next sign-in. See [Settings](/docs/settings).
