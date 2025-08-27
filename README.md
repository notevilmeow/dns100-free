# PyDNS UI — Simple Authoritative/Forwarding DNS Server with Web UI

A fully functional DNS server written in Python with a beautiful Flask web UI.
- Authoritative zones with A/AAAA/CNAME/MX/TXT/NS/SRV records
- Optional forwarding (recursive) to upstream DNS when no local match is found
- SQLite storage; import/export BIND zone files
- Live query log and search
- One-command run

> **Note:** The app listens on UDP port **5353** by default (unprivileged). You can change it in **Settings**. If you want to listen on port 53 you must run as root or set a port-forwarding rule on your OS/firewall.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

- Web UI: http://127.0.0.1:8000
- DNS Server: UDP 0.0.0.0:5353 (configurable in UI Settings)

## Features

- Create/edit/delete zones
- Create/edit/delete records (A, AAAA, CNAME, MX, TXT, NS, SRV)
- SOA fields managed per-zone (serial auto-bumps on changes)
- Optional forwarding to upstream DNS (e.g., 1.1.1.1 or 8.8.8.8)
- Live query log (client IP, qname, qtype, answer/rcode, duration)
- Built-in DNS test tool
- Export/import BIND zone files
- Simple JSON API (documented in the code)

## Security

This sample is intentionally simple and **does not include authentication**. For production, place the UI behind a reverse proxy with auth (or extend the app).

## Running on Port 53 (optional)

Linux example to forward port 53 to 5353 without root app:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
```

## License

MIT
