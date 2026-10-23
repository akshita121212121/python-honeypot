# Python Honeypot

A low-interaction honeypot that imitates SSH, Telnet and HTTP services,
records what attackers try, and produces a summary report.

> Run only on machines and networks you own, inside an isolated VM,
> as a non-root user. It never executes attacker input.

## Features
- Fake SSH banner (port 2222)
- Fake Telnet login that records usernames and passwords (port 2323)
- Fake HTTP router login page that records requests and form data (port 8080)
- JSON-lines logging to honeypot.log
- Built-in report: top IPs, usernames, passwords, user agents, activity by hour

## Usage
    python3 honeypot.py            # start the honeypot
    python3 honeypot.py --report   # analyze honeypot.log

## Test locally
    nc 127.0.0.1 2323
    curl http://127.0.0.1:8080

## What I learned
(add after you collect data)

## Future work
- Capture SSH credentials with paramiko
- IP geolocation and reputation lookups
- Alerting
- Map findings to MITRE ATT&CK (T1110 Brute Force)
