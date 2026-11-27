#!/usr/bin/env python3
"""API driver and assertions for the Azure e2e suite (e2e/azure/run.sh).

Talks to the bundle through the SSH tunnel run.sh opens (Caddy's TEST-ONLY
e2e overlay stamps the admin identity, so no sign-in). Standard library only.
Every assertion prints one "PASS"/"FAIL" line and exits non-zero on failure.
The first argument is always the tunnel's local URL (https://localhost:<port>).

  rh_e2e.py <url> setup <ssh_host>                        settings for devices on the VNet
  rh_e2e.py integration                              every integration check passes (recording may skip)
  rh_e2e.py code <mode> <name> <expected_os> <out.json>
  rh_e2e.py wait-used <enrollment_id> <timeout_s>    prints the device id
  rh_e2e.py device <device_id> [--transport T] [--os O] [--online true|false]
                   [--client-contains S] [--hostname H] [--code-shown TEXT_FILE]
  rh_e2e.py wait-online <device_id> <true|false> <timeout_s>
  rh_e2e.py svc <device_id> <kind> <port> <username> <password_file>
  rh_e2e.py probe <device_id> <kind> <ok|fail>
  rh_e2e.py guac <device_id> <kind>                  connect, then redeem at /guacamole/api/tokens
  rh_e2e.py enr-state <enrollment_id> <state>
  rh_e2e.py no-dup-with <device_id> <other_device_id>
  rh_e2e.py audit-has <event> <outcome>
"""
import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = ""  # set from argv[1] (the tunnel's local URL, e.g. https://localhost:9443)
_ctx = ssl.create_default_context()
_ctx.check_hostname, _ctx.verify_mode = False, ssl.CERT_NONE  # Caddy's local CA, through a loopback tunnel
_op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                  urllib.request.HTTPSHandler(context=_ctx))


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def ok(what):
    say(f"PASS {what}")


def fail(what):
    say(f"FAIL {what}")
    sys.exit(1)


def call(method, path, body=None, headers=None, form=None):
    if form is not None:
        data, ctype = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    else:
        data, ctype = (json.dumps(body).encode() if body is not None else None), "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", ctype)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _op.open(req, timeout=60) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw) if raw else {}
    except ValueError:
        return status, {"raw": raw.decode(errors="replace")[:300]}


def csrf():
    return call("GET", "/api/v1/me")[1]["data"]["csrf_token"]


def data(path):
    s, r = call("GET", path)
    if s != 200:
        fail(f"GET {path} -> {s} {r}")
    return r["data"]


def mutate(method, path, body, extra=None):
    h = {"X-CSRF-Token": csrf()}
    h.update(extra or {})
    return call(method, path, body, h)


def flags(argv):
    out, i = {}, 0
    while i < len(argv):
        out[argv[i].lstrip("-")] = argv[i + 1]
        i += 2
    return out


def main(a):
    cmd = a[0]
    if cmd == "setup":
        st = data("/api/v1/settings")
        s, r = mutate("PATCH", "/api/v1/settings", {"public_url": BASE, "ssh_public_host": a[1], "ssh_public_port": 2222},
                      {"If-Match": st["etag"]})
        ok("settings: public URL and SSH host") if s == 200 else fail(f"settings -> {s} {r}")
    elif cmd == "integration":
        checks = data("/api/v1/integration").get("checks", [])
        bad = [c for c in checks if c.get("status") not in ("pass", "skip")]
        ok(f"integration: {len(checks)} checks pass") if checks and not bad else fail(f"integration: {bad or 'no checks'}")
    elif cmd == "code":
        mode, name, os_, out = a[1], a[2], a[3], a[4]
        body = {"name": name, "mode": mode, "ttl_minutes": 60}
        if os_ != "any":
            body["expected_os"] = os_
        s, r = mutate("POST", "/api/v1/enrollments", body)
        if s != 201 or not r["data"]["ssh"]["unix"]:
            fail(f"create {mode} code -> {s} {r}")
        d = r["data"]
        if mode == "attended" and (d["command_unix"] or d["command_windows"]):
            fail("attended code carries script commands")
        with open(out, "w") as f:
            json.dump(d, f)
        ok(f"{mode} code for {name}")
    elif cmd == "wait-used":
        deadline = time.time() + float(a[2])
        while time.time() < deadline:
            e = data(f"/api/v1/enrollments/{a[1]}")
            if e["state"] == "used" and e["device_id"]:
                say(e["device_id"])
                return
            time.sleep(2)
        fail(f"enrollment {a[1]} not used within {a[2]} s")
    elif cmd == "device":
        d, f = data(f"/api/v1/devices/{a[1]}"), flags(a[2:])
        problems = []
        if "transport" in f and d["transport"] != f["transport"]:
            problems.append(f"transport {d['transport']}")
        if "os" in f and d["os"] != f["os"]:
            problems.append(f"os {d['os']}")
        if "online" in f and d["online"] != (f["online"] == "true"):
            problems.append(f"online {d['online']}")
        if "client-contains" in f and f["client-contains"] not in d["client_version"]:
            problems.append(f"client {d['client_version']}")
        if "hostname" in f and d["hostname"].lower() != f["hostname"].lower():
            problems.append(f"hostname {d['hostname']}")
        if "code-shown" in f:
            shown = open(f["code-shown"]).read()
            if not d["connection_code"] or f"Connection code: {d['connection_code']}" not in shown:
                problems.append(f"connection code {d['connection_code']!r} not in the person's terminal")
        what = f"device {d['name']} ({d['transport']}, {d['os']}, {d['client_version']}, code {d['connection_code'] or '-'})"
        fail(f"{what}: {', '.join(problems)}") if problems else ok(what)
    elif cmd == "wait-online":
        want, deadline = a[2] == "true", time.time() + float(a[3])
        while time.time() < deadline:
            if data(f"/api/v1/devices/{a[1]}")["online"] == want:
                ok(f"device {a[1]} online={want}")
                return
            time.sleep(2)
        fail(f"device {a[1]} not online={want} within {a[3]} s")
    elif cmd == "svc":
        pw = open(a[5]).read().strip()
        s, r = mutate("PUT", f"/api/v1/devices/{a[1]}/services/{a[2]}", {"remote_port": int(a[3]), "username": a[4], "password": pw})
        ok(f"saved {a[2]} login") if s == 200 else fail(f"save {a[2]} login -> {s} {r}")
    elif cmd == "probe":
        s, r = mutate("POST", f"/api/v1/devices/{a[1]}/probe", {})
        res = {x["service"]: x for x in r.get("data", [])}
        x = res.get(a[2])
        if s != 200 or x is None or x["ok"] != (a[3] == "ok"):
            fail(f"probe {a[2]} want {a[3]}: {s} {x or r}")
        ok(f"probe {a[2]} {a[3]} through the tunnel ({x.get('banner') or x.get('hint', '')[:40]})")
    elif cmd == "guac":
        s, r = mutate("POST", f"/api/v1/devices/{a[1]}/connect", {"service": a[2]})
        if s != 200:
            fail(f"connect {a[2]} -> {s} {r}")
        blob = urllib.parse.parse_qs(urllib.parse.urlparse(r["data"]["url"]).query).get("data", [""])[0] \
            or r["data"]["url"].split("data=", 1)[-1]
        s2, r2 = call("POST", "/guacamole/api/tokens", form={"data": blob})
        if s2 != 200 or not r2.get("authToken") or r2.get("dataSource") != "json":
            fail(f"guacamole token for {a[2]} -> {s2} {r2}")
        ok(f"Guacamole accepted the {a[2]} connection (json data source)")
    elif cmd == "enr-state":
        st = data(f"/api/v1/enrollments/{a[1]}")["state"]
        ok(f"enrollment {a[1]} is {st}") if st == a[2] else fail(f"enrollment {a[1]} is {st}, want {a[2]}")
    elif cmd == "no-dup-with":
        ws = [w for w in data(f"/api/v1/devices/{a[1]}")["identity_warnings"] if w.get("other_device_id") == a[2]]
        ok("ended one-time session not flagged as a duplicate") if not ws else fail(f"duplicate warning: {ws}")
    elif cmd == "audit-has":
        rows = data("/api/v1/audit?page_size=200")
        hit = any(e.get("event") == a[1] and e.get("outcome") == a[2] for e in rows)
        ok(f"audit has {a[1]} {a[2]}") if hit else fail(f"audit lacks {a[1]} {a[2]}")
    else:
        fail(f"unknown command {cmd}")


if __name__ == "__main__":
    BASE = sys.argv[1].rstrip("/")
    main(sys.argv[2:])
