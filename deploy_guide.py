#!/usr/bin/env python3
"""Deploy target guide to lab machine via SSH."""
import paramiko
import sys

HOST = "192.168.124.130"
PORT = 22
USER = "test"
PASS = "123456"

def ssh_exec(ssh, cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15, banner_timeout=15)
        print("[+] Connected via SSH")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    # Explore
    rc, out, err = ssh_exec(ssh, "whoami && id && ls -la /home/test/ | head -30")
    print(f"=== whoami & home dir ===\n{out}")
    if err: print(f"ERR: {err}")

    rc, out, err = ssh_exec(ssh, "ls -la /")
    print(f"=== root dir ===\n{out}")
    if err: print(f"ERR: {err}")

    # Check services
    rc, out, err = ssh_exec(ssh, "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")
    print(f"=== listening ===\n{out}")
    if err: print(f"ERR: {err}")

    # Check docker
    rc, out, err = ssh_exec(ssh, "docker ps --format '{{.Names}} | {{.Ports}}' 2>/dev/null")
    print(f"=== docker ===\n{out}")
    if err: print(f"ERR: {err}")

    ssh.close()
    print("[+] Done")

if __name__ == "__main__":
    main()
