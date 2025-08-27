import os
import threading
import time
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from dns_server import DNSServerThread, send_test_dns_query, ensure_db, bump_zone_serial, export_zone_to_bind, import_zone_from_bind

DB_PATH = os.environ.get("PYDNS_DB", "data.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PYDNS_SECRET", "dev-secret")

dns_thread = None

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def startup():
    """Initialize DB and DNS thread."""
    global dns_thread
    ensure_db(DB_PATH)
    if dns_thread is None or not dns_thread.is_alive():
        dns_thread = DNSServerThread(DB_PATH)
        dns_thread.daemon = True
        dns_thread.start()
    send_test_dns_query("192.168.85.175", "meow")

@app.route("/")
def index():
    conn = get_db()
    zones = conn.execute("SELECT * FROM zones ORDER BY name").fetchall()
    stats = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
    settings = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row["key"]: row["value"] for row in settings}
    return render_template("index.html", zones=zones, stats=stats, settings=settings)

@app.route("/settings", methods=["GET", "POST"])
def settings():
    conn = get_db()
    if request.method == "POST":
        listen_addr = request.form.get("listen_addr","0.0.0.0")
        listen_port = int(request.form.get("listen_port","5353"))
        upstream = request.form.get("upstream","")
        default_ttl = int(request.form.get("default_ttl","300"))
        kv = {
            "listen_addr": listen_addr,
            "listen_port": str(listen_port),
            "upstream": upstream,
            "default_ttl": str(default_ttl),
        }
        with conn:
            for k,v in kv.items():
                conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k,v))
        flash("Settings saved. DNS server will restart.", "success")
        restart_dns()
        return redirect(url_for("settings"))
    settings = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {row["key"]: row["value"] for row in settings}
    if "listen_addr" not in settings:
        settings.update({"listen_addr":"0.0.0.0","listen_port":"5353","upstream":"","default_ttl":"300"})
    return render_template("settings.html", settings=settings)

def restart_dns():
    global dns_thread
    if dns_thread and dns_thread.is_alive():
        dns_thread.stop()
        dns_thread.join(timeout=2)
    dns_thread = DNSServerThread(DB_PATH)
    dns_thread.daemon = True
    dns_thread.start()

@app.route("/zones/new", methods=["GET","POST"])
def new_zone():
    conn = get_db()
    if request.method == "POST":
        name = request.form["name"].strip().rstrip(".") + "."
        ttl = int(request.form.get("ttl","300"))
        primary_ns = request.form.get("primary_ns","ns1."+name).strip().rstrip(".") + "."
        admin_email = request.form.get("admin_email","admin."+name).replace("@",".")
        refresh = int(request.form.get("refresh","3600"))
        retry = int(request.form.get("retry","600"))
        expire = int(request.form.get("expire","86400"))
        minimum = int(request.form.get("minimum","300"))
        with conn:
            conn.execute("""INSERT INTO zones(name, ttl, primary_ns, admin_email, serial, refresh, retry, expire, minimum)
            VALUES(?,?,?,?,strftime('%s','now'),?,?,?,?)""", (name, ttl, primary_ns, admin_email, refresh, retry, expire, minimum))
        flash("Zone created.", "success")
        restart_dns()
        return redirect(url_for("index"))
    return render_template("zone_form.html", zone=None)

@app.route("/zones/<int:zone_id>")
def view_zone(zone_id):
    conn = get_db()
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
    if not zone:
        flash("Zone not found", "danger")
        return redirect(url_for("index"))
    records = conn.execute("SELECT * FROM records WHERE zone_id=? ORDER BY name, type", (zone_id,)).fetchall()
    return render_template("zone.html", zone=zone, records=records)

@app.route("/zones/<int:zone_id>/edit", methods=["GET","POST"])
def edit_zone(zone_id):
    conn = get_db()
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
    if request.method == "POST":
        name = request.form["name"].strip().rstrip(".") + "."
        ttl = int(request.form.get("ttl","300"))
        primary_ns = request.form.get("primary_ns","").strip().rstrip(".") + "."
        admin_email = request.form.get("admin_email","").replace("@",".")
        refresh = int(request.form.get("refresh","3600"))
        retry = int(request.form.get("retry","600"))
        expire = int(request.form.get("expire","86400"))
        minimum = int(request.form.get("minimum","300"))
        with conn:
            conn.execute("""UPDATE zones SET name=?, ttl=?, primary_ns=?, admin_email=?, refresh=?, retry=?, expire=?, minimum=? WHERE id=?""",
                         (name, ttl, primary_ns, admin_email, refresh, retry, expire, minimum, zone_id))
            bump_zone_serial(conn, zone_id)
        flash("Zone updated.", "success")
        restart_dns()
        return redirect(url_for("view_zone", zone_id=zone_id))
    return render_template("zone_form.html", zone=zone)

@app.route("/zones/<int:zone_id>/delete", methods=["POST"])
def delete_zone(zone_id):
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM records WHERE zone_id=?", (zone_id,))
        conn.execute("DELETE FROM zones WHERE id=?", (zone_id,))
    flash("Zone deleted.", "warning")
    restart_dns()
    return redirect(url_for("index"))

@app.route("/zones/<int:zone_id>/records/new", methods=["GET","POST"])
def new_record(zone_id):
    conn = get_db()
    if request.method == "POST":
        name = request.form["name"].strip()
        rtype = request.form["type"].strip().upper()
        content = request.form["content"].strip()
        ttl = int(request.form.get("ttl","0") or 0)
        priority = request.form.get("priority")
        priority = int(priority) if priority else None
        with conn:
            conn.execute("""INSERT INTO records(zone_id, name, type, content, ttl, priority) VALUES(?,?,?,?,?,?)""",
                         (zone_id, name, rtype, content, ttl, priority))
            bump_zone_serial(conn, zone_id)
        flash("Record added.", "success")
        restart_dns()
        return redirect(url_for("view_zone", zone_id=zone_id))
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
    return render_template("record_form.html", zone=zone, record=None)

@app.route("/records/<int:record_id>/edit", methods=["GET","POST"])
def edit_record(record_id):
    conn = get_db()
    rec = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
    if request.method == "POST":
        name = request.form["name"].strip()
        rtype = request.form["type"].strip().upper()
        content = request.form["content"].strip()
        ttl = int(request.form.get("ttl","0") or 0)
        priority = request.form.get("priority")
        priority = int(priority) if priority else None
        with conn:
            conn.execute("""UPDATE records SET name=?, type=?, content=?, ttl=?, priority=? WHERE id=?""",
                         (name, rtype, content, ttl, priority, record_id))
            bump_zone_serial(conn, rec["zone_id"])
        flash("Record updated.", "success")
        restart_dns()
        return redirect(url_for("view_zone", zone_id=rec["zone_id"]))
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (rec["zone_id"],)).fetchone()
    return render_template("record_form.html", zone=zone, record=rec)

@app.route("/records/<int:record_id>/delete", methods=["POST"])
def delete_record(record_id):
    conn = get_db()
    rec = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
    with conn:
        conn.execute("DELETE FROM records WHERE id=?", (record_id,))
        bump_zone_serial(conn, rec["zone_id"])
    flash("Record deleted.", "warning")
    restart_dns()
    return redirect(url_for("view_zone", zone_id=rec["zone_id"]))

@app.route("/logs")
def logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("logs.html", rows=rows)

@app.route("/api/logs")
def api_logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/test", methods=["GET","POST"])
def test_tool():
    result = None
    if request.method == "POST":
        qname = request.form["qname"]
        qtype = request.form.get("qtype","A")
        server = request.form.get("server","127.0.0.1")
        port = int(request.form.get("port","5353"))
        import dns.resolver
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.port = port
            answer = resolver.resolve(qname, qtype)
            result = [r.to_text() for r in answer]
        except Exception as e:
            result = [f"Error: {e}"]
    return render_template("test.html", result=result)

@app.route("/zones/<int:zone_id>/export")
def export_zone(zone_id):
    conn = get_db()
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
    if not zone:
        return "Not found", 404
    content = export_zone_to_bind(conn, zone_id)
    path = f"/mnt/data/{zone['name']}.zone"
    open(path,"w").write(content)
    return send_file(path, as_attachment=True, download_name=f"{zone['name']}.zone", mimetype="text/plain")

@app.route("/zones/import", methods=["GET","POST"])
def import_zone():
    conn = get_db()
    if request.method == "POST":
        f = request.files["zonefile"]
        text = f.read().decode()
        zid = import_zone_from_bind(conn, text)
        flash("Zone imported.", "success")
        restart_dns()
        return redirect(url_for("view_zone", zone_id=zid))
    return render_template("import.html")


if __name__ == "__main__":
    print(f"Using database at: {DB_PATH}")   # debug line
    with app.app_context():
        ensure_db(DB_PATH)
        startup()
        
    app.run(host="127.0.0.1", port=8000, debug=True)
