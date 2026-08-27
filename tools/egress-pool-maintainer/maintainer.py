#!/usr/bin/env python3
"""Egress pool maintainer for grok2api.

Discovers free proxies, validates them against Grok/xAI targets (not AO3),
scores them in a local sqlite DB, imports healthy ones as egress nodes via
the admin API, and periodically sweeps unhealthy nodes.

Stdlib-only. Config via environment variables:
  GROK2API_ADMIN_URL    admin API base, e.g. http://127.0.0.1:18000
  GROK2API_ADMIN_USER   default "admin"
  GROK2API_ADMIN_PASS   admin password
  GROK2API_SCOPE        egress scope, default "grok_build"
  GROK2API_POOL_DB      sqlite path, default ./egress-pool.db
  POOL_MAX_NODES        max egress nodes to keep healthy, default 60
  POOL_VALIDATION_TARGETS  comma-separated URLs to validate against
  POOL_CONCURRENCY      validation threads, default 40
  POOL_TIMEOUT          per-request timeout, default 8
  POOL_REFRESH_EVERY    seconds between discovery runs, default 600
  POOL_SWEEP_EVERY      seconds between node sweeps, default 300
"""

import concurrent.futures as cf
import json
import os
import random
import sqlite3
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
    "concurrency": int(os.getenv("POOL_CONCURRENCY", "40")),
    "timeout": float(os.getenv("POOL_TIMEOUT", "8")),
    "refresh_every": int(os.getenv("POOL_REFRESH_EVERY", "600")),
    "sweep_every": int(os.getenv("POOL_SWEEP_EVERY", "300")),
}

SOURCES = {
    "http": [
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    ],
    "socks5": [
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ],
}

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
        data = self._request("GET", f"/api/admin/v1/egress-nodes?scope={urllib.parse.quote(self.scope())}")
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
        """Delete disabled/unhealthy nodes that no account uses (keeps DB from growing unbounded)."""
        self.ensure_token()
        try:
            data = self._request("POST", "/api/admin/v1/egress-nodes/cleanup")
            value = data.get("data", {})
            if value.get("deleted"):
                log(f"cleanup: purged {value['deleted']} dead node(s)")
        except Exception as e:
            log(f"cleanup: {type(e).__name__}: {e}")


def fetch_proxies():
    """Fetch fresh proxy URLs from free sources."""
    all_raw = []

    def fetch(proto, url):
        try:
            resp = http_get(url, timeout=CONFIG["timeout"] + 4)
            text = resp.read().decode("utf-8", "replace")
            return [f"{proto}://{line.strip()}" for line in text.splitlines() if line.strip()]
        except Exception:
            return []

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(fetch, proto, u) for proto, urls in SOURCES.items() for u in urls]
        for f in futs:
            all_raw.extend(f.result())

    return list(dict.fromkeys(all_raw))


def validate_proxy(url):
    """Return True if proxy reaches at least one grok target (any HTTP status)."""
    if "://" not in url:
        return False
    for target in CONFIG["targets"]:
        try:
            resp = http_get(target, timeout=CONFIG["timeout"], proxy=url)
            return resp.status < 500
        except urllib.error.HTTPError as e:
            # 401/400/403/404 from the server means the proxy tunnel worked;
            # the request reached the target. Treat as reachable.
            if e.code in (400, 401, 403, 404):
                return True
            return False
        except Exception:
            continue
    return False


def sweep_nodes(client, store):
    """Disable unhealthy nodes; keep only the best pool."""
    nodes = client.list_nodes()
    enabled = [n for n in nodes if n.get("enabled")]
    if not enabled:
        return
    log(f"sweep: {len(enabled)} enabled nodes, max target {CONFIG['max_nodes']}")

    # Node URL is not returned (encrypted), but accountCapacity/name and
    # probe status are. Disable nodes that failed their last probe.
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
    # Delete disabled/unhealthy nodes no longer in use so the DB doesn't grow
    # without bound across discovery cycles.
    client.purge_unhealthy()


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
                raw = fetch_proxies()
                log(f"discovery: fetched {len(raw)} raw proxy lines")

                candidates = [u for u in raw if u not in store.best(0)]
                candidates = candidates[:max(50, CONFIG["max_nodes"] * 4)]
                log(f"discovery: validating {len(candidates)} new candidates")

                results = {}
                with cf.ThreadPoolExecutor(max_workers=CONFIG["concurrency"]) as ex:
                    futs = {ex.submit(validate_proxy, u): u for u in candidates}
                    for f in cf.as_completed(futs):
                        results[futs[f]] = f.result()

                ok = [u for u, good in results.items() if good]
                fail = [u for u, good in results.items() if not good]
                for u in ok:
                    store.upsert_result(u, True)
                for u in fail:
                    store.upsert_result(u, False)
                log(f"discovery: {len(ok)}/{len(candidates)} reached grok targets")

                room = CONFIG["max_nodes"] - len(healthy)
                if room > 0 and ok:
                    to_import = ok[:room]
                    content = "\n".join(to_import)
                    res = client.import_proxies(f"pool-{int(time.time())}", content)
                    log(f"import: {res.get('imported', 0)} nodes imported, {res.get('skipped', 0)} skipped")
                    ids = [n["id"] for n in client.list_nodes()
                           if n.get("probeStatus") == "unknown"][:len(to_import)]
                    if ids:
                        t = client.test_nodes(ids)
                        log(f"probe: {t.get('healthy', 0)} healthy, {t.get('unhealthy', 0)} unhealthy")

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
