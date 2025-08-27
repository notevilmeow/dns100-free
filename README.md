# PyDNS UI — The Only DNS You’ll Ever Need

Forget Google, Cloudflare, and all those boring DNS servers — this baby runs right on **Windows** and it’s blazing fast. Built with Python + Flask, it gives you a clean web UI so you can see all your DNS zones in one place.

* Authoritative zones with A/AAAA/CNAME/MX/TXT/NS/SRV records
* Optional forwarding if you want to be fancy
* SQLite backend, because who wants a heavy DB?
* Live query log (see everyone who’s looking at your stuff)
* One-command setup — easy peasy

> **Pro Tip:** By default, this listens on UDP **5353**. Wanna be cool and use 53? Run as admin or set a firewall rule.

## Quickstart (Windows Edition)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

* Web UI: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* DNS Server: UDP 0.0.0.0:5353 (you can change it in Settings)

## Features

* Full control: create/edit/delete zones & records
* SOA serial auto-bumps on changes (magic!)
* Forward to any upstream DNS you like (even your neighbor’s if you dare)
* Live query log — track all the sneaky visitors
* Built-in DNS test tool (because testing is fun)
* Import/export BIND zone files
* Simple JSON API for those who like to hack stuff

## Security

None. Nada. Zip. This is sample code. If you want **real** security, put a reverse proxy in front or add auth. Or don’t — live on the edge.

## License

MIT (Meow Is Tech)