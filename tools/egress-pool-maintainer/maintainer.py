#!/usr/bin/env python3
"""Egress pool maintainer for grok2api.

Discovers free proxies from quality sources (metadata-rich APIs first),
validates them against Grok/xAI targets, scores them in a local sqlite DB,
imports the best ones as egress nodes via the admin API, and periodically
sweeps unhealthy nodes.

Stdlib-only (SOCKS5 validated via a hand-rolled CONNECT tunnel, no PySocks).
Config via environment variables (see CONFIG below).

Source strategy (2026-08 upgrade):
  - HProxy API: uptime/latency/anonymity-filtered, sort=uptime. Best signal.
  - ProxyScrape v4 API: timeout-filtered, updated every minute.
  - proxmint: small but rigorously re-validated every 30 min (score field).
  - proxifly + monosans GitHub lists: volume fallback via jsDelivr CDN.
  Dead/legacy sources removed: ShiftyTR (dead repo), ProxyScrape v2,
  clarketm, TheSpeedX (stale; monosans supersedes it for http).
"""

import concurrent.futures as cf
import json
import os
import random
import socket
import sqlite3
import ssl
import threading
import time
import urllib.request
import urllib.error
import urllib.parse

CONFIG = {
    "api_url": os.getenv("GROK2API_ADMIN_URL", "http://127.0.0.1:18000"),
    "user": os.getenv("GROK2API_ADMIN_USER", "admin"),
    "password": os.getenv("GROK2API_ADMIN_PASS", ""),
    "scope": os.getenv("GROK2API_SCOPE", "grok_build"),
    "pool_db": os.getenv("GROK2API_POOL_DB", "./egress-pool.db"),
    "max_nodes": int(os.getenv("POOL_MAX_NODES", "60")),
    "targets": [t.strip() for t in os.getenv(
        "POOL_VALIDATION_TARGETS",
        "https://cli-chat-proxy.grok.com/v1/models,"
        "https://grok.com/robots.txt",
    ).split(",") if t.strip()],
    # Mirror of the gateway's own probe (infra/egress/manager.go): a node is
    # only healthy if it can fetch the Cloudflare trace endpoint through the
    # proxy with a 2xx and a parseable exit IP. Pre-validating this in the
    # maintainer avoids importing nodes the gateway will immediately sweep.
    "probe_targets": [t.strip() for t in os.getenv(
        "POOL_PROBE_TARGETS",
        "https://1.1.1.1/cdn-cgi/trace,"
        "https://ipinfo.io/json",
    ).split(",") if t.strip()],
    "concurrency": int(os.getenv("POOL_CONCURRENCY", "40")),
    "timeout": float(os.getenv("POOL_TIMEOUT", "8")),
    "refresh_every": int(os.getenv("POOL_REFRESH_EVERY", "600")),
    "sweep_every": int(os.getenv("POOL_SWEEP_EVERY", "300")),
    # Only import candidates whose measured grok-target latency is at or
    # below this (ms). 0 disables the filter.
    "max_import_latency_ms": int(os.getenv("POOL_MAX_IMPORT_LATENCY_MS", "2500")),
    # Cap per /24 subnet so one hijacked network block cannot dominate the pool.
    "max_per_subnet": int(os.getenv("POOL_MAX_PER_SUBNET", "4")),
}

# Quality sources, tried in order. Each entry: (name, url, kind)
# kind: "txt:<proto>"  -> plain lines of ip:port, prefixed with proto
#        "hproxy"      -> HProxy JSON API (rich metadata)
#        "proxmint"    -> proxmint JSON API (score/uptime metadata)
HPROXY_PARAMS = "protocol=http,https,socks5&min_uptime_pct=80&max_latency_ms=2500&sort=uptime&limit=10000&format=json"

SOURCES = [
    # --- Tier 1: pre-filtered, metadata-rich ---
    ("hproxy", f"https://hproxy.com/api/proxy-list?{HPROXY_PARAMS}", "hproxy"),
    ("proxyscrape-v4-http", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=http&timeout=5000", "txt:http"),
    ("proxyscrape-v4-socks5", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks5&timeout=5000", "txt:socks5"),
    ("proxmint", "https://proxmint.com/api/free-proxies?format=json&limit=1000", "proxmint"),
    # --- Tier 2: volume fallbacks ---
    ("proxifly-all", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt", "txt:auto"),
    ("monosans-http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "txt:http"),
    ("monosans-socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "txt:socks5"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def http_get(url, timeout=10, proxy=None):
    req = urllib.request.Request(url, headers={
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
    })
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        opener = urllib.request.build_opener(handler)
    else:
        opener = urllib.request.build_opener()
    return opener.open(req, timeout=timeout)


# ---------------------------------------------------------------------------
# SOCKS5 support (stdlib-only): minimal CONNECT tunnel used for validation.
# ---------------------------------------------------------------------------

def socks5_fetch(host, port, target_host, target_port, path, timeout, use_tls=True):
    """Open a SOCKS5 CONNECT tunnel to target_host:target_port, optionally
    TLS-wrap it, and GET path. Returns (status, body) or raises."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        # Greeting: ver=5, 1 method, no-auth (0x00)
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] == 0xFF:
            raise ConnectionError("socks5 handshake refused")
        # CONNECT request: ver=5, cmd=connect(1), rsv=0, atyp=domain(3)
        addr = target_host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + target_port.to_bytes(2, "big"))
        head = sock.recv(4)
        if len(head) < 4 or head[1] != 0x00:
            raise ConnectionError("socks5 connect failed")
        # Drain the bound address based on atyp
        atyp = head[3]
        if atyp == 0x01:
            sock.recv(4 + 2)
        elif atyp == 0x03:
            nlen = sock.recv(1)
            sock.recv(nlen[0] + 2)
        elif atyp == 0x04:
            sock.recv(16 + 2)
        conn = sock
        if use_tls:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(sock, server_hostname=target_host)
        req = (f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        conn.sendall(req.encode())
        chunks = []
        while True:
            data = conn.recv(65536)
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
        try:
            head_end = raw.index(b"\r\n\r\n")
        except ValueError:
            raise ConnectionError("no http response")
        status_line = raw[:raw.index(b"\r\n")].decode("latin-1")
        status = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
        return status, raw[head_end + 4:]
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _http_reachable(targets, url, timeout):
    """True if the proxy fetches any target with a tunnel-working status."""
    for target in targets:
        try:
            resp = http_get(target, timeout=timeout, proxy=url)
            if resp.status < 500:
                return True
        except urllib.error.HTTPError as e:
            # 400/401/403/404 means the tunnel worked; request reached target
            if e.code in (400, 401, 403, 404):
                return True
        except Exception:
            continue
    return False


def _probe_exit_ip(url, timeout):
    """Mirror the gateway probe: fetch 1.1.1.1/cdn-cgi/trace through the
    proxy; return latency_ms if 2xx and an ip= line parses, else None."""
    try:
        start = time.time()
        resp = http_get("https://1.1.1.1/cdn-cgi/trace", timeout=timeout, proxy=url)
        body = resp.read().decode("utf-8", "replace")
        latency = int((time.time() - start) * 1000)
        if not (200 <= resp.status < 300):
            return None
        for line in body.splitlines():
            if line.startswith("ip=") and line[3:].strip():
                return latency
        # ipinfo.io-style JSON fallback
        try:
            import json as _json
            data = _json.loads(body)
            if data.get("ip"):
                return latency
        except Exception:
            pass
        return None
    except Exception:
        return None


def validate_proxy(candidate):
    """Validate a candidate dict {url, proto, source, src_uptime, src_latency}.
    Must pass BOTH the gateway-mirroring probe (Cloudflare trace, 2xx + exit
    IP) and grok-target reachability. Returns candidate with ok + latency_ms."""
    url = candidate["url"]
    proto = candidate["proto"]
    start = time.time()
    if proto.startswith("socks5"):
        # SOCKS5: full gateway-mirroring probe through a hand-rolled tunnel
        try:
            status, body = socks5_fetch(candidate["host"], candidate["port"],
                                        "1.1.1.1", 443, "/cdn-cgi/trace", CONFIG["timeout"])
            if not (200 <= status < 300):
                return dict(candidate, ok=False, latency_ms=None)
            body_text = body.decode("utf-8", "replace")
            if not any(line.startswith("ip=") and line[3:].strip() for line in body_text.splitlines()):
                return dict(candidate, ok=False, latency_ms=None)
            latency = int((time.time() - start) * 1000)
            return dict(candidate, ok=True, latency_ms=latency)
        except Exception:
            return dict(candidate, ok=False, latency_ms=None)
    # HTTP(S): gateway-mirroring probe first (this is what decides node health)
    probe_latency = _probe_exit_ip(url, CONFIG["timeout"])
    if probe_latency is None:
        return dict(candidate, ok=False, latency_ms=None)
    # Then grok-target reachability (what the account traffic actually needs)
    if not _http_reachable(CONFIG["targets"], url, CONFIG["timeout"]):
        return dict(candidate, ok=False, latency_ms=None)
    return dict(candidate, ok=True, latency_ms=probe_latency)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def parse_proxy_url(url):
    """http://1.2.3.4:8080 -> dict(host, port, proto). None if malformed."""
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname or parts.port is None:
            return None
        proto = (parts.scheme or "http").lower()
        if proto not in ("http", "https", "socks4", "socks5"):
            return None
        return {"host": parts.hostname, "port": parts.port, "proto": proto}
    except Exception:
        return None


def fetch_source(name, url, kind):
    """Fetch one source; return list of candidate dicts."""
    candidates = []
    try:
        resp = http_get(url, timeout=CONFIG["timeout"] + 7)
        text = resp.read().decode("utf-8", "replace")
    except Exception as e:
        log(f"  source {name}: failed ({type(e).__name__})")
        return []

    if kind == "hproxy":
        try:
            data = json.loads(text)
            for p in data:
                protos = p.get("protocols") or []
                proto = "socks5" if "socks5" in protos else ("http" if "http" in protos or "https" in protos else None)
                if not proto:
                    continue
                candidates.append({
                    "url": f"{proto}://{p['ip']}:{p['port']}",
                    "host": p["ip"], "port": p["port"], "proto": proto,
                    "source": name,
                    "src_uptime": p.get("uptime_pct") or 0,
                    "src_latency": p.get("latency_ms") or 0,
                })
        except Exception as e:
            log(f"  source {name}: parse error ({e})")
    elif kind == "proxmint":
        try:
            data = json.loads(text)
            for p in data.get("rows", []):
                proto = (p.get("protocol") or "http").lower()
                if proto not in ("http", "socks5"):
                    continue
                candidates.append({
                    "url": f"{proto}://{p['ip']}:{p['port']}",
                    "host": p["ip"], "port": p["port"], "proto": proto,
                    "source": name,
                    "src_uptime": p.get("uptimePct") or 0,
                    "src_latency": p.get("latencyMs") or 0,
                })
        except Exception as e:
            log(f"  source {name}: parse error ({e})")
    else:
        # txt:<proto> or txt:auto (proxifly all.txt uses proto://ip:port lines)
        proto_hint = kind.split(":", 1)[1] if ":" in kind else "http"
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "://" in line:
                parsed = parse_proxy_url(line)
                if parsed:
                    candidates.append({
                        "url": line, "host": parsed["host"], "port": parsed["port"],
                        "proto": parsed["proto"], "source": name,
                        "src_uptime": 0, "src_latency": 0,
                    })
            else:
                # bare ip:port
                try:
                    host, port = line.rsplit(":", 1)
                    port = int(port)
                except Exception:
                    continue
                proto = proto_hint if proto_hint != "auto" else "http"
                candidates.append({
                    "url": f"{proto}://{host}:{port}",
                    "host": host, "port": port, "proto": proto, "source": name,
                    "src_uptime": 0, "src_latency": 0,
                })
    return candidates


def fetch_proxies():
    """Fetch all sources in parallel; dedupe by url, prefer richer sources."""
    all_candidates = {}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(fetch_source, name, url, kind): name for name, url, kind in SOURCES}
        for fut in cf.as_completed(futs):
            for c in fut.result():
                key = c["url"]
                existing = all_candidates.get(key)
                if existing is None or c["src_uptime"] > existing["src_uptime"]:
                    all_candidates[key] = c
    return list(all_candidates.values())


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def url_to_candidate(url):
    """Rebuild a minimal candidate dict from a stored proxy URL."""
    parsed = parse_proxy_url(url)
    if not parsed:
        return {"url": url, "host": "", "port": 0, "proto": "http",
                "source": "db", "src_uptime": 0, "src_latency": 0}
    return {"url": url, "host": parsed["host"], "port": parsed["port"],
            "proto": parsed["proto"], "source": "db",
            "src_uptime": 0, "src_latency": 0}


def subnet24(host):
    """Return the /24 subnet of an IPv4 host, or the host itself otherwise."""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ".".join(parts[:3])
    return host


def rank_candidates(candidates, store):
    """Rank validated candidates: source uptime first, then measured latency.
    Applies per-/24-subnet cap to avoid one network block dominating."""
    # Prefer proven proxies from our own DB history
    history = {row[0]: row[1] for row in store.history()}
    ranked = []
    for c in candidates:
        if not c.get("ok"):
            continue
        lat = c.get("latency_ms") or 99999
        if CONFIG["max_import_latency_ms"] and lat > CONFIG["max_import_latency_ms"]:
            continue
        own = history.get(c["url"], 0.0)
        # Score: own success rate dominates, then source uptime, then latency
        score = own * 1000 + (c.get("src_uptime") or 0) * 10 - lat / 100.0
        ranked.append((score, c))
    ranked.sort(key=lambda x: -x[0])

    selected, subnet_counts = [], {}
    for score, c in ranked:
        sn = subnet24(c["host"])
        if subnet_counts.get(sn, 0) >= CONFIG["max_per_subnet"]:
            continue
        subnet_counts[sn] = subnet_counts.get(sn, 0) + 1
        selected.append(c)
    return selected


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class PoolStore:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                url TEXT PRIMARY KEY,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                last_checked TIMESTAMP,
                last_ok TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        """)
        self.conn.commit()

    def upsert_result(self, url, ok):
        with self.lock:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            row = self.conn.execute(
                "SELECT success_count, failure_count FROM proxies WHERE url = ?",
                (url,),
            ).fetchone()
            if row:
                sc, fc = row
                if ok:
                    sc += 1
                else:
                    fc += 1
                last_ok = now if ok else None
                self.conn.execute(
                    "UPDATE proxies SET success_count=?, failure_count=?, last_checked=?, "
                    "last_ok=COALESCE(?, last_ok), is_active=1 WHERE url=?",
                    (sc, fc, now, last_ok, url),
                )
            else:
                self.conn.execute(
                    "INSERT INTO proxies (url, success_count, failure_count, last_checked, "
                    "last_ok, is_active) VALUES (?, ?, ?, ?, ?, 1)",
                    (url, 1 if ok else 0, 0 if ok else 1, now, now if ok else None),
                )
            self.conn.commit()

    def deactivate(self, urls):
        if not urls:
            return
        with self.lock:
            self.conn.executemany(
                "UPDATE proxies SET is_active=0 WHERE url=?", [(u,) for u in urls]
            )
            self.conn.commit()

    def history(self):
        """url -> own success rate (0..1) for ranking."""
        with self.lock:
            return [
                (r[0], r[1] / max(1, r[2]))
                for r in self.conn.execute(
                    "SELECT url, success_count, success_count + failure_count FROM proxies "
                    "WHERE is_active=1 AND success_count + failure_count >= 2"
                ).fetchall()
            ]

    def proven_urls(self, limit):
        """Best historically-successful proxy URLs (Bayesian success rate)."""
        with self.lock:
            return [
                r[0] for r in self.conn.execute(
                    "SELECT url FROM proxies WHERE is_active=1 AND success_count >= 1 "
                    "ORDER BY ((success_count + 1.0) / (success_count + failure_count + 2.0)) DESC, "
                    "success_count DESC LIMIT ?", (limit,)
                ).fetchall()
            ]

    def best(self, limit):
        with self.lock:
            return [
                r[0] for r in self.conn.execute(
                    "SELECT url FROM proxies WHERE is_active=1 "
                    "ORDER BY ((success_count + 1.0) / (success_count + failure_count + 2.0)) DESC, "
                    "last_checked ASC LIMIT ?", (limit,)
                ).fetchall()
            ]

    def active_count(self):
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM proxies WHERE is_active=1"
            ).fetchone()[0]


# ---------------------------------------------------------------------------
# Admin client
# ---------------------------------------------------------------------------

class GrokAdminClient:
    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.token = None

    def _login(self):
        body = json.dumps({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(
            f"{self.base}/api/admin/v1/auth/login",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        tokens = data["data"]["tokens"]
        self.token = tokens["accessToken"]

    def _request(self, method, path, payload=None, retry_auth=True):
        def once():
            headers = {"Authorization": f"Bearer {self.token}"}
            data = None
            if payload is not None:
                data = json.dumps(payload).encode()
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                f"{self.base}{path}", data=data, headers=headers, method=method
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}

        try:
            return once()
        except urllib.error.HTTPError as e:
            if e.code == 401 and retry_auth:
                self._login()
                return once()
            raise

    def ensure_token(self):
        if self.token is None:
            self._login()

    def list_nodes(self):
        self.ensure_token()
        query = urllib.parse.quote(self.scope())
        # Explicit pageSize: the API default truncates large pools.
        data = self._request("GET", f"/api/admin/v1/egress-nodes?scope={query}&pageSize=500")
        return data.get("data", {}).get("items", [])

    def scope(self):
        return CONFIG["scope"]

    def import_proxies(self, name, content):
        self.ensure_token()
        data = self._request("POST", "/api/admin/v1/egress-imports", {
            "name": name,
            "scope": self.scope(),
            "accountCapacity": 0,
            "content": content,
        })
        return data.get("data", {})

    def test_nodes(self, ids):
        self.ensure_token()
        data = self._request("POST", "/api/admin/v1/egress-nodes/test", {"ids": [str(i) for i in ids]})
        return data.get("data", {})

    def update_enabled(self, ids, enabled):
        self.ensure_token()
        data = self._request("PATCH", "/api/admin/v1/egress-nodes/batch", {
            "ids": [str(i) for i in ids],
            "enabled": enabled,
        })
        return data.get("data", {})

    def purge_unhealthy(self):
        """Delete disabled/unhealthy nodes that no account uses (keeps DB bounded)."""
        self.ensure_token()
        try:
            data = self._request("POST", "/api/admin/v1/egress-nodes/cleanup")
            value = data.get("data", {})
            if value.get("deleted"):
                log(f"cleanup: purged {value['deleted']} dead node(s)")
        except Exception as e:
            log(f"cleanup: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def sweep_nodes(client, store):
    """Disable unhealthy nodes; keep only the best pool."""
    nodes = client.list_nodes()
    enabled = [n for n in nodes if n.get("enabled")]
    if not enabled:
        return
    log(f"sweep: {len(enabled)} enabled nodes, max target {CONFIG['max_nodes']}")

    bad = []
    for n in enabled:
        pv4 = (n.get("ipv4Probe") or {}).get("status")
        pv6 = (n.get("ipv6Probe") or {}).get("status")
        status = n.get("probeStatus")
        if pv4 == "unhealthy" and pv6 == "unhealthy":
            bad.append(n["id"])
        elif status == "unhealthy":
            bad.append(n["id"])
    if bad:
        res = client.update_enabled(bad, False)
        log(f"sweep: disabled {res.get('updated', 0)} unhealthy nodes")
        for n in enabled:
            if n["id"] in bad:
                name = n.get("name", "")
                if name:
                    store.deactivate([name])
    client.purge_unhealthy()


def discovery_cycle(client, store, healthy_count):
    """One discovery+validation+import cycle. Returns nothing."""
    raw = fetch_proxies()
    log(f"discovery: fetched {len(raw)} unique candidates from {len(SOURCES)} sources")

    # Phase 1: re-validate proven proxies from our own DB (highest priority).
    # They passed before; a quick re-check confirms they are still alive.
    proven = store.proven_urls(max(200, CONFIG["max_nodes"] * 3))
    proven_set = set(proven)
    raw_urls = {c["url"] for c in raw}
    # Prefer proven proxies that still appear in live source lists; fall back
    # to proven DB entries (sources rotate, good proxies may drop off lists).
    proven_live = [u for u in proven if u in raw_urls]
    proven_stale = [u for u in proven if u not in raw_urls][:100]
    recheck = proven_live + proven_stale
    if recheck:
        log(f"discovery: re-validating {len(recheck)} proven proxies from DB")
        recheck_cands = [url_to_candidate(u) for u in recheck]
        results = []
        with cf.ThreadPoolExecutor(max_workers=CONFIG["concurrency"]) as ex:
            futs = [ex.submit(validate_proxy, c) for c in recheck_cands]
            for f in cf.as_completed(futs):
                results.append(f.result())
        ok_proven = [r for r in results if r and r.get("ok")]
        for r in results:
            if r:
                store.upsert_result(r["url"], bool(r.get("ok")))
        log(f"discovery: {len(ok_proven)}/{len(recheck)} proven proxies still alive")

    # Phase 2: validate fresh candidates not yet in the DB.
    known = {u for u, _ in store.history()}
    candidates = [c for c in raw if c["url"] not in known and c["url"] not in proven_set]
    # Tier-1 sources first (they carry src_uptime), then volume sources
    candidates.sort(key=lambda c: -(c.get("src_uptime") or 0))
    candidates = candidates[:max(80, CONFIG["max_nodes"] * 4)]
    log(f"discovery: validating {len(candidates)} new candidates")

    results = []
    with cf.ThreadPoolExecutor(max_workers=CONFIG["concurrency"]) as ex:
        futs = [ex.submit(validate_proxy, c) for c in candidates]
        for f in cf.as_completed(futs):
            results.append(f.result())

    ok = ok_proven + [r for r in results if r and r.get("ok")]
    fail = [r for r in results if r and not r.get("ok")]
    for r in fail:
        store.upsert_result(r["url"], False)
    log(f"discovery: {len(ok)} total validated "
        f"({len(ok_proven)} proven + {len(ok) - len(ok_proven)}/{len(candidates)} new)")

    selected = rank_candidates(ok, store)
    log(f"discovery: {len(selected)} passed ranking "
        f"(latency<={CONFIG['max_import_latency_ms']}ms, max {CONFIG['max_per_subnet']}/subnet)")

    room = CONFIG["max_nodes"] - healthy_count
    if room > 0 and selected:
        to_import = selected[:room]
        content = "\n".join(c["url"] for c in to_import)
        res = client.import_proxies(f"pool-{int(time.time())}", content)
        log(f"import: {res.get('imported', 0)} nodes imported, {res.get('skipped', 0)} skipped")
        ids = [n["id"] for n in client.list_nodes()
               if n.get("probeStatus") == "unknown"][:len(to_import)]
        if ids:
            t = client.test_nodes(ids)
            log(f"probe: {t.get('healthy', 0)} healthy, {t.get('unhealthy', 0)} unhealthy")


def main():
    if not CONFIG["password"]:
        log("GROK2API_ADMIN_PASS not set; aborting")
        return 1

    store = PoolStore(CONFIG["pool_db"])
    client = GrokAdminClient(CONFIG["api_url"], CONFIG["user"], CONFIG["password"])
    try:
        client.ensure_token()
        log(f"connected to {CONFIG['api_url']}")
    except Exception as e:
        log(f"login failed: {e}")
        return 1

    last_refresh = 0.0
    last_sweep = 0.0

    while True:
        now = time.time()
        try:
            nodes = client.list_nodes()
            healthy = [n for n in nodes if n.get("enabled") and n.get("probeStatus") != "unhealthy"]
            log(f"nodes: {len(healthy)} healthy / {len(nodes)} total, active in pool {store.active_count()}")

            if now - last_refresh >= CONFIG["refresh_every"]:
                last_refresh = now
                discovery_cycle(client, store, len(healthy))

            if now - last_sweep >= CONFIG["sweep_every"]:
                last_sweep = now
                sweep_nodes(client, store)

        except Exception as e:
            log(f"error: {type(e).__name__}: {e}")

        time.sleep(30)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
