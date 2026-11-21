# RemoteHound website

The project's one-page website: what RemoteHound is for, how it works (setting a machine up, connecting,
and where Apache Guacamole fits), features, screenshots of Linux, macOS and Windows sessions and the
console, and why it was built next to MeshCentral.

```
website/
├── index.html       # the page (a template: install-specific URLs are {{PLACEHOLDERS}})
├── img/             # screenshots, and the mascot/mark/favicon written by tools/brand/build.mjs
├── deploy.sh        # render the template with local/website.env and publish it
└── README.md
```

- **No scripts, no external requests.** Styles are inline; images are local. It serves under a strict
  CSP (`default-src 'none'; img-src 'self'; style-src 'unsafe-inline'`).
- **Placeholders, not domains.** This repo keeps owner data out (`ci/check-public.mjs`), so the console
  and MeshCentral URLs, and the sign-in note, are filled in at deploy time from the git-ignored
  `local/website.env`. The header of `deploy.sh` lists its keys.
- **Screenshots** come from a local test bundle (example data only: `remote.example.com`, demo device
  names). `linux-ssh.jpg` is a real SSH session to an Ubuntu container enrolled with the one-liner;
  `windows-desktop.jpg` a real Windows 11 RDP session. A macOS Screen Sharing shot is still wanted: take
  it from a Mac whose screen has nothing personal on it, save it as `img/macos-desktop.jpg`
  (1600 × 1000) and add a tile next to the Linux one.
  Retake them after a visible UI change; keep them 1600 × 1000 (the phone shot 780 × 1688), JPEG.
- **Artwork**: don't edit `img/*.svg` by hand — change `tools/brand/build.mjs` and re-run it
  (see `docs/BRAND.md`).

Publish: `website/deploy.sh --dry-run` to see what would change, then `website/deploy.sh`.
