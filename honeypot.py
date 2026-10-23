#!/usr/bin/env python3
"""Low-interaction honeypot: fake SSH banner, fake Telnet login, fake HTTP login.
Run inside an isolated VM, as a normal (non-root) user, on high ports.
"""

import argparse
import json
import socket
import threading
from datetime import datetime, timezone

LOG_FILE = "honeypot.log"
log_lock = threading.Lock()

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

HTTP_LOGIN_PAGE = b"""<html><head><title>Router Admin</title></head>
<body><h2>Router Login</h2>
<form method="POST" action="/login">
User: <input name="user"><br>Pass: <input name="pass" type="password"><br>
<input type="submit" value="Login"></form></body></html>"""


def log_event(service, addr, event, **data):
    record = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "service": service,
        "src_ip": addr[0],
        "src_port": addr[1],
        "event": event,
        **data,
    }
    line = json.dumps(record)
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
        print(line)


def read_line(conn, limit=256):
    buf = b""
    while len(buf) < limit and not buf.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").strip()


def handle_ssh(conn, addr):
    conn.sendall(SSH_BANNER)
    data = conn.recv(512)
    log_event("ssh", addr, "client_hello",
              data=data.decode(errors="replace").strip()[:200])


def handle_telnet(conn, addr):
    for _ in range(3):
        conn.sendall(b"login: ")
        user = read_line(conn)
        if not user:
            return
        conn.sendall(b"Password: ")
        password = read_line(conn)
        log_event("telnet", addr, "login_attempt",
                  username=user[:64], password=password[:64])
        conn.sendall(b"\r\nLogin incorrect\r\n")


def handle_http(conn, addr):
    request = conn.recv(4096).decode(errors="replace")
    if not request:
        return
    first_line = request.splitlines()[0][:200]
    headers, _, body = request.partition("\r\n\r\n")
    user_agent = next(
        (h.split(":", 1)[1].strip() for h in headers.splitlines()
         if h.lower().startswith("user-agent")), "")
    log_event("http", addr, "request",
              request_line=first_line, user_agent=user_agent[:150],
              body=body[:200])
    conn.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\nConnection: close\r\n\r\n"
        + HTTP_LOGIN_PAGE
    )


def serve(name, port, handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    print(f"[+] {name} honeypot listening on port {port}")

    def client_thread(conn, addr):
        log_event(name, addr, "connection")
        conn.settimeout(15)
        try:
            handler(conn, addr)
        except (OSError, socket.timeout):
            pass
        finally:
            conn.close()

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=client_thread, args=(conn, addr),
                         daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description="Low-interaction honeypot")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--telnet-port", type=int, default=2323)
    parser.add_argument("--http-port", type=int, default=8080)
    args = parser.parse_args()

    services = [
        ("ssh", args.ssh_port, handle_ssh),
        ("telnet", args.telnet_port, handle_telnet),
        ("http", args.http_port, handle_http),
    ]
    for name, port, handler in services:
        threading.Thread(target=serve, args=(name, port, handler),
                         daemon=True).start()

    print(f"Logging to {LOG_FILE}. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()

