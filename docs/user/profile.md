# Profile

Your profile is where you manage your own account. Open it by selecting your name at the bottom of the sidebar, or **More → Profile** on a phone.

## Appearance

Choose **System**, **Light** or **Dark**. *System* follows your device's setting. The choice is saved to your account, so it follows you to other browsers.

## Sign-in methods

This lists every provider linked to your account, with the email it reported and when you linked it.

- **Link** adds another provider. You are sent to that provider to sign in, then come back here.
- **Unlink** removes one. You must always keep at least one method; if you try to remove the last one, RemoteHound refuses and says so.

If your organisation signs you in through its own proxy, there is nothing to link here.

## My saved logins

A saved login is your own username and password for one service (SSH, RDP or VNC) on one device.

> Connect uses your own login, so you get your own session; nobody — admins included — can read it.

1. Select **Save a login**.
2. Choose the **Device** and the **Service**. Only devices you can connect to, and only the services each device offers, are listed.
3. Enter the **Username** and **Password** you use on that device, then select **Save login**.

The password is encrypted for you alone and never shown again — to change anything, type the password again. Select a saved login to edit or delete it.

**SSH keys.** Many Linux servers accept keys only (no passwords). For an SSH service you can paste a **private key** instead: the whole key, from `-----BEGIN … PRIVATE KEY-----` to the `END` line. If the key has a passphrase, put it in the password box; otherwise leave the password empty. The device must list the matching public key in that user's `~/.ssh/authorized_keys`. Use a key made for RemoteHound, not your personal one: it is stored encrypted for you alone, but a dedicated key can be revoked on its own.

You can also save a login from a device's page: select **Use my own login** below its Connect button.

Saved logins need permission to connect to devices (Operator or Admin role).
