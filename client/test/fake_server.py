#!/usr/bin/env python3
"""Tiny stand-in for the RemoteHound enrol API, used by client/test/run.sh (stdlib only).

  POST /api/v1/enroll          validates the EnrollRequest strictly, returns 201 {"data": EnrollResult}
  GET  /api/v1/enroll/status   checks device_id + fingerprint; "online" becomes true on the 2nd poll

Every request is appended as one JSON line to the --record file so the harness can inspect exactly
what the bootstrap sent. Special codes trigger error paths:
  usedzz  -> 410 problem+json ENROLL_CODE_USED
  badzzz  -> 201 with a hostile device_id      (client must refuse)
  badfwd  -> 201 with a hostile forward        (client must refuse)
  badhst  -> 201 with a hostile ssh_host       (client must refuse)
"""
import argparse
import base64
import hashlib
import json
import os
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CODE_RE = re.compile(r"^[a-hjkmnp-z2-9]{6}\Z")
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}\Z")
SERVER_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QtaG9zdC1rZXktbm90LXJlYWwtMDAwMDAwMA"  # gitleaks:allow (fake public host key fixture)
LOCK = threading.Lock()
DEVICES = {}  # device_id -> {"fingerprint":..., "polls": int, "forwards": [...]}
ARGS = None


def fingerprint(pub):
    blob = base64.b64decode(pub.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def validate(b):
    errs = []
    if not isinstance(b, dict):
        return ["body is not an object"]
    allowed = {"code", "public_key", "hostname", "os", "os_version", "services", "client_version",
               "install_scope", "install_user"}
    errs += ["unknown field %s" % k for k in b if k not in allowed]
    if not isinstance(b.get("code"), str) or not CODE_RE.match(b["code"]):
        errs.append("code")
    pk = b.get("public_key")
    if not isinstance(pk, str) or not pk.startswith("ssh-ed25519 ") or len(pk) > 1024:
        errs.append("public_key")
    else:
        try:
            fingerprint(pk)
        except Exception:  # noqa: BLE001 - any decode failure means a bad key
            errs.append("public_key base64")
    if not isinstance(b.get("hostname"), str) or not HOST_RE.match(b["hostname"]):
        errs.append("hostname")
    if b.get("os") not in ("linux", "macos", "windows", "unknown"):
        errs.append("os")
    if not isinstance(b.get("os_version"), str) or len(b["os_version"]) > 128:
        errs.append("os_version")
    svcs = b.get("services")
    if not isinstance(svcs, list) or not (1 <= len(svcs) <= 8):
        errs.append("services")
    else:
        for s in svcs:
            if (not isinstance(s, dict) or set(s) != {"kind", "remote_port"}
                    or s["kind"] not in ("ssh", "rdp", "vnc")
                    or not isinstance(s["remote_port"], int) or isinstance(s["remote_port"], bool)
                    or not 1 <= s["remote_port"] <= 65535):
                errs.append("service %r" % (s,))
    if b.get("client_version") != "1":
        errs.append("client_version")
    if b.get("install_scope") not in ("system", "user"):
        errs.append("install_scope")
    iu = b.get("install_user")
    if not isinstance(iu, str) or len(iu) > 64 or (b.get("install_scope") == "system" and iu):
        errs.append("install_user")
    return errs


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output quiet
        pass

    def record(self, entry):
        with LOCK, open(ARGS.record, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def send_json(self, status, obj, ctype="application/json"):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def problem(self, status, code, detail):
        self.send_json(status, {"type": "about:blank", "title": code, "status": status,
                                "detail": detail, "code": code}, "application/problem+json")

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
        entry = {"method": "POST", "path": self.path, "content_type": self.headers.get("Content-Type"),
                 "user_agent": self.headers.get("User-Agent"), "raw": raw}
        if self.path != "/api/v1/enroll":
            self.record(entry)
            return self.problem(404, "NOT_FOUND", "no such endpoint")
        try:
            body = json.loads(raw)
        except ValueError as e:
            entry["errors"] = ["invalid json: %s" % e]
            self.record(entry)
            return self.problem(400, "BAD_REQUEST", "invalid JSON")
        errs = validate(body)
        entry["errors"] = errs
        self.record(entry)
        if errs:
            return self.problem(400, "ENROLL_KEY_INVALID", "invalid request: " + ", ".join(errs))
        code = body["code"]
        if code == "usedzz":
            return self.problem(410, "ENROLL_CODE_USED", "This code has already been used.")
        dev = "dev_" + hashlib.sha256((code + body["public_key"]).encode()).hexdigest()[:12]
        fwd = ["%d:localhost:%d" % (s["remote_port"], s["remote_port"]) for s in body["services"]]
        res = {"device_id": dev, "device_name": "Test é \"" + body["hostname"] + "\"",
               "ssh_host": "rh.test.invalid", "ssh_port": 2222,
               "known_hosts_line": "[rh.test.invalid]:2222 ssh-ed25519 " + SERVER_KEY,
               "forwards": fwd, "fingerprint": fingerprint(body["public_key"])}
        if code == "badzzz":
            res["device_id"] = "dev_x;touch /tmp/rh-pwned"
        elif code == "badfwd":
            res["forwards"] = fwd + ["-oProxyCommand=touch /tmp/rh-pwned"]
        elif code == "badhst":
            res["ssh_host"] = "-oProxyCommand=touch"
        with LOCK:
            DEVICES[dev] = {"fingerprint": res["fingerprint"], "polls": 0, "forwards": fwd}
        self.send_json(201, {"data": res})

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        entry = {"method": "GET", "path": u.path, "query": {k: v[0] for k, v in q.items()}}
        self.record(entry)
        if u.path != "/api/v1/enroll/status":
            return self.problem(404, "NOT_FOUND", "no such endpoint")
        dev = q.get("device_id", [""])[0]
        fpr = q.get("fingerprint", [""])[0]
        with LOCK:
            d = DEVICES.get(dev)
            if not d or d["fingerprint"] != fpr:
                return self.problem(404, "NOT_FOUND", "unknown device or fingerprint")
            d["polls"] += 1
            online = d["polls"] >= 2
            fwd = d["forwards"]
        self.send_json(200, {"data": {"online": online, "forwards": fwd if online else []}})


def main():
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--port-file", required=True)
    p.add_argument("--record", required=True)
    ARGS = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(ARGS.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(ARGS.port_file + ".tmp", ARGS.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
