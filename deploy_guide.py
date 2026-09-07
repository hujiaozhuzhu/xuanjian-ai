#!/usr/bin/env python3
"""Deploy target guide to lab machine via SSH/SFTP using paramiko."""
import paramiko
import sys
import os

HOST = "192.168.124.130"
PORT = 22
USER = "test"
PASS = "123456"
LOCAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "REPORT_TARGET_GUIDE.md")
REMOTE_PATH = "/home/test/README.md"


def main():
    print(f"[*] Connecting to {HOST}:{PORT} ...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST, port=PORT, username=USER, password=PASS,
                    timeout=20, banner_timeout=15)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)
    print("[+] Connected")

    # Upload via SFTP
    sftp = ssh.open_sftp()
    sftp.put(LOCAL_FILE, REMOTE_PATH)
    sftp.close()
    print(f"[+] Uploaded {LOCAL_FILE} -> {REMOTE_PATH}")

    # Verify upload
    stdin, stdout, stderr = ssh.exec_command(
        f"ls -la {REMOTE_PATH} && wc -l {REMOTE_PATH} && head -5 {REMOTE_PATH}", timeout=10
    )
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(f"[*] Remote file info:\n{out}")
    if err:
        print(f"[!] stderr: {err}")

    ssh.close()
    print("[+] Done")


if __name__ == "__main__":
    main()
