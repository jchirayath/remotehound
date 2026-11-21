# local/ — never committed

Owner-specific data stays here (git-ignored except this README):

- `denylist.txt` — one term per line (your domains, hostnames, IPs, email addresses, internal names);
  `re:` prefix = case-insensitive regex. `ci/check-public.mjs` blocks any commit that adds one of them.
- deployment notes, real `.env` files, keys.
