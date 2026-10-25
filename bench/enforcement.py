"""Checks EDL Manager's time-to-enforcement metric against ground truth.

Simulated firewalls poll the IP list on a fixed interval and note when each
entry first appears in what they download. Meanwhile entries are submitted
and approved through the API at random intervals. Ground truth for an entry =
the first poll, by any firewall, whose list contains it, minus its approval
time. EDL Manager's own figures come from GET /api/v1/metrics. Prints JSON
with both. Standard library only.

Usage: python3 bench/enforcement.py <base URL> <API key> [approvals] [poll seconds] [firewalls]
"""

import json
import random
import sys
import threading
import time
import urllib.request
from datetime import datetime

BASE, KEY = sys.argv[1], sys.argv[2]
APPROVALS = int(sys.argv[3]) if len(sys.argv) > 3 else 24
POLL_SECONDS = float(sys.argv[4]) if len(sys.argv) > 4 else 20
FIREWALLS = int(sys.argv[5]) if len(sys.argv) > 5 else 3
random.seed(2026)  # the same approval schedule on every run

first_seen: dict[str, float] = {}
lock = threading.Lock()
stop = threading.Event()


def api(method, path, body=None):
    request = urllib.request.Request(
        BASE + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def firewall(number):
    """Polls every POLL_SECONDS, staggered so the firewalls don't poll together."""
    time.sleep(number * POLL_SECONDS / FIREWALLS)
    while not stop.is_set():
        polled_at = time.time()
        request = urllib.request.Request(
            BASE + "/edl-files/ip_blocklist.txt", headers={"User-Agent": f"simulated-firewall-{number}"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            entries = response.read().decode().split()
        with lock:
            for entry in entries:
                first_seen.setdefault(entry, polled_at)
        stop.wait(POLL_SECONDS)


def percentile(values, pct):
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))  # nearest rank, as the metrics page uses
    return ordered[rank - 1]


pollers = [threading.Thread(target=firewall, args=(n,), daemon=True) for n in range(FIREWALLS)]
for poller in pollers:
    poller.start()
time.sleep(POLL_SECONDS + 2)  # every firewall has polled once: tracking covers what follows

approved_at = {}
fields = {"justification": "Accuracy check", "servicenow_ticket": "INC0000001"}
for i in range(APPROVALS):
    time.sleep(random.uniform(4, 16))
    entry = f"198.18.1.{i + 1}"
    request_id = api("POST", "/api/v1/requests", {"entry": entry, **fields})["data"]["created"][0]["id"]
    record = api("POST", f"/api/v1/requests/{request_id}/approve", {})["data"]
    approved_at[entry] = datetime.fromisoformat(record["approved_at"]).timestamp()

time.sleep(POLL_SECONDS + 5)  # the last approval reaches a firewall
stop.set()

# EDL Manager stores whole seconds, so truth is compared at whole seconds too.
truth = [int(first_seen[entry]) - int(approved_at[entry]) for entry in approved_at if entry in first_seen]
reported = api("GET", "/api/v1/metrics?days=1")["data"]["time_to_enforcement"]
print(
    json.dumps(
        {
            "benchmark": "enforcement_accuracy",
            "approvals": APPROVALS,
            "firewalls": FIREWALLS,
            "poll_seconds": POLL_SECONDS,
            "ground_truth": {
                "count": len(truth),
                "median_seconds": percentile(truth, 50),
                "p90_seconds": percentile(truth, 90),
                "min_seconds": min(truth),
                "max_seconds": max(truth),
                "values": sorted(truth),
            },
            "reported": reported,
            "match": reported["count"] == len(truth)
            and reported["median_seconds"] == percentile(truth, 50)
            and reported["p90_seconds"] == percentile(truth, 90),
        },
        indent=2,
    )
)
