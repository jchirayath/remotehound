#!/usr/bin/env python3
"""Run C:\\rh\\test.cmd on a Windows VM as a real user over WinRM (NTLM) and keep
that cmd session open, like a person leaving the window open, until <stop_file>
exists (or 2 h, WinRM's idle limit). Runs on the e2e server VM, which shares the
Windows VM's subnet. Copies what the person would see to <out_file> as it goes.

  winrm_hold.py <windows_ip> <user> <password_file> <out_file> <stop_file>

Why not az vm run-command: it runs as SYSTEM (no real profile), and Windows
refuses explicit-credential logons started from SYSTEM ("logon session does not
exist"). WinRM from outside is an ordinary logon with the user's profile.
"""
import os
import sys
import time

from winrm.protocol import Protocol

ip, user, pw_file, out_file, stop_file = sys.argv[1:6]
p = Protocol(endpoint=f"http://{ip}:5985/wsman", transport="ntlm", username=user,
             password=open(pw_file).read().strip(), server_cert_validation="ignore",
             operation_timeout_sec=60, read_timeout_sec=70)


def run(cmdline):
    sh = p.open_shell()
    cid = p.run_command(sh, "cmd.exe", ["/c", cmdline])
    out, err, _ = p.get_command_output(sh, cid)
    p.cleanup_command(sh, cid)
    p.close_shell(sh)
    return (out + err).decode(errors="replace")


if os.path.exists(stop_file):
    os.remove(stop_file)
run("del C:\\rh\\out.txt 2>nul")
shell = p.open_shell()
cid = p.run_command(shell, "cmd.exe", ["/c", "C:\\rh\\test.cmd > C:\\rh\\out.txt 2>&1"])
deadline = time.time() + 7200
while time.time() < deadline and not os.path.exists(stop_file):
    with open(out_file, "w") as f:
        f.write(run("type C:\\rh\\out.txt 2>nul"))
    time.sleep(3)
with open(out_file, "w") as f:
    f.write(run("type C:\\rh\\out.txt 2>nul"))
# Ends cmd and ssh: the person closing the window. A shell that is already
# gone (WinRM timeout) needs no cleanup, so that error is reported, not raised.
try:
    p.cleanup_command(shell, cid)
    p.close_shell(shell)
except Exception as e:  # nosemgrep: std.py.swallowed-exception -- reported on stdout; the shell may already be gone
    sys.stdout.write(f"cleanup: {e}\n")
