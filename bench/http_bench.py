"""HTTP benchmarks for a running EDL Manager: list downloads with and without
fetch tracking, and REST API latency. Standard library only; prints JSON.

Usage: python3 bench/http_bench.py <base URL> <API key> <entries loaded>
"""

import http.client
import json
import sys
import threading
import time
import urllib.parse

BASE, KEY, ENTRIES = sys.argv[1], sys.argv[2], int(sys.argv[3])
URL = urllib.parse.urlsplit(BASE)
SECONDS = 10
CONCURRENCY = [1, 8]


def connect() -> http.client.HTTPConnection:
    return http.client.HTTPConnection(URL.hostname, URL.port, timeout=60)


def call(conn, method, path, body=None, headers=None):
    headers = dict(headers or {})
    if body is not None:
        body = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    return response.status, data


def percentile(seconds, pct):
    ordered = sorted(seconds)
    rank = max(1, -(-pct * len(ordered) // 100))  # nearest rank
    return round(ordered[rank - 1] * 1000, 2)


def summary(seconds, elapsed=None, errors=0):
    result = {"requests": len(seconds), "p50_ms": percentile(seconds, 50), "p95_ms": percentile(seconds, 95)}
    if elapsed:
        result["requests_per_second"] = round(len(seconds) / elapsed, 1)
    result["errors"] = errors
    return result


def load(path, concurrency, user_agent):
    """Each thread keeps a connection and downloads `path` for SECONDS.
    user_agent(thread, i) picks the client identity for request i."""
    latencies, errors, lock = [], [0], threading.Lock()
    deadline = time.monotonic() + SECONDS

    def worker(thread):
        conn, mine, i = connect(), [], 0
        while time.monotonic() < deadline:
            start = time.perf_counter()
            status, _ = call(conn, "GET", path, headers={"User-Agent": user_agent(thread, i)})
            mine.append(time.perf_counter() - start)
            i += 1
            if status != 200:
                with lock:
                    errors[0] += 1
        with lock:
            latencies.extend(mine)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(concurrency)]
    start = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return summary(latencies, time.monotonic() - start, errors[0])


def downloads():
    scenarios = {
        # Apache serving a copy of the IP list as a plain file: the baseline.
        "static_file": ("/edl-files/static_ip.txt", lambda t, i: f"bench-fw-{t}"),
        # feed.php, each thread one firewall: tracking writes at most once a minute per client.
        "feed_tracked": ("/edl-files/ip_blocklist.txt", lambda t, i: f"bench-fw-{t}"),
        # feed.php, every request a new client: a tracking write on every request (worst case).
        "feed_new_client_every_request": ("/edl-files/ip_blocklist.txt", lambda t, i: f"bench-fw-{t}-{i}"),
    }
    load("/edl-files/static_ip.txt", 2, lambda t, i: "warm-up")  # warm up Apache and OPcache
    return {
        name: {f"concurrency_{c}": load(path, c, agent) for c in CONCURRENCY}
        for name, (path, agent) in scenarios.items()
    }


def api():
    conn, auth = connect(), {"Authorization": f"Bearer {KEY}"}
    timings = {"submit_one": [], "approve": [], "submit_500": [], "metrics": [], "entries_page": []}
    ids = []

    def timed(name, method, path, body=None):
        start = time.perf_counter()
        status, data = call(conn, method, path, body, auth)
        timings[name].append(time.perf_counter() - start)
        if status >= 300:
            raise SystemExit(f"{method} {path} returned {status}: {data[:200]!r}")
        return json.loads(data)

    fields = {"justification": "Benchmark", "servicenow_ticket": "INC0000001"}
    for i in range(100):  # 198.18.0.0/15 is reserved for benchmarking (RFC 2544)
        created = timed("submit_one", "POST", "/api/v1/requests", {"entry": f"198.18.0.{i + 1}", **fields})
        ids.append(created["data"]["created"][0]["id"])
    for request_id in ids:
        timed("approve", "POST", f"/api/v1/requests/{request_id}/approve", {})
    for run in range(5):
        entries = [f"198.19.{run}.{i}" for i in range(1, 251)] + [f"198.19.{run + 100}.{i}" for i in range(1, 251)]
        timed("submit_500", "POST", "/api/v1/requests", {"entries": entries, **fields})
    for _ in range(20):
        timed("metrics", "GET", "/api/v1/metrics?days=30")
        timed("entries_page", "GET", "/api/v1/entries?limit=100")
    return {name: summary(seconds) for name, seconds in timings.items()}


print(
    json.dumps(
        {
            "benchmark": "http",
            "entries_loaded": ENTRIES,
            "seconds_per_download_run": SECONDS,
            "downloads": downloads(),
            "api": api(),
        },
        indent=2,
    )
)
