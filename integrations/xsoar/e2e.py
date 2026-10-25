"""Runs every EDLManager command through main() against a live EDL Manager,
the way Cortex XSOAR would. Called by e2e.sh inside the XSOAR runtime image.

Usage: python e2e.py <EDL Manager URL> <API key>
"""

import sys

import demistomock as demisto
import EDLManager
import requests

BASE, KEY = sys.argv[1], sys.argv[2]
ERROR_ENTRY = 4
captured: list = []
demisto.results = captured.append
demisto.params = lambda: {"url": BASE, "credentials": {"password": KEY}}
failures = 0


def run(command: str, **args) -> dict:
    captured.clear()
    demisto.command = lambda: command
    demisto.args = lambda: {name: str(value) for name, value in args.items()}
    try:
        EDLManager.main()
    except SystemExit:  # return_error() exits after reporting
        pass
    entry = captured[-1]
    return {"HumanReadable": entry, "EntryContext": {}, "Type": 1} if isinstance(entry, str) else entry


def check(label: str, condition: bool, detail: object = "") -> None:
    global failures
    print(f"{'ok  ' if condition else 'FAIL'} {label}" + ("" if condition else f": {detail}"))  # noqa: T201 (test report)
    failures += 0 if condition else 1


def context(entry: dict, prefix: str):
    return next((value for key, value in entry["EntryContext"].items() if key.startswith(prefix)), None)


def firewall_fetch() -> None:
    requests.get(f"{BASE}/edl-files/ip_blocklist.txt", headers={"User-Agent": "PAN-OS e2e"}, timeout=10)


firewall_fetch()  # start fetch tracking before anything is approved

result = run("test-module")
check("test-module", result["HumanReadable"] == "ok", result)

result = run(
    "edl-manager-request-submit",
    entries="203.0.113.10,phish.example.org,https://login.example.net/verify,999.1.1.1",
    justification="Phishing campaign from incident 4821",
    servicenow_ticket="SIR0004821",
    priority="high",
)
created = context(result, "EDLManager.Request") or []
skipped = context(result, "EDLManager.SkippedEntry") or []
check("request-submit creates three requests", len(created) == 3, result)
check("request-submit skips the invalid entry", [s["Entry"] for s in skipped] == ["999.1.1.1"], skipped)
ip_request, domain_request, url_request = (request["ID"] for request in created[:3])

result = run("edl-manager-request-submit", entries="203.0.113.10", justification="again", servicenow_ticket="SIR0004821")
check("request-submit with nothing new is not an error", result["Type"] != ERROR_ENTRY, result)

result = run("edl-manager-request-list", limit=10)
check("request-list", len(context(result, "EDLManager.Request") or []) == 3, result)

result = run("edl-manager-request-get", request_id=url_request)
check("request-get (pending)", (context(result, "EDLManager.Request") or {}).get("Status") == "pending", result)

result = run("edl-manager-request-approve", request_id=ip_request, comment="Confirmed")
entry = context(result, "EDLManager.Entry") or {}
check("request-approve", entry.get("Status") == "active", result)

result = run("edl-manager-request-deny", request_id=domain_request, reason="False positive")
check("request-deny", (context(result, "EDLManager.Request") or {}).get("Status") == "denied", result)

result = run("edl-manager-request-get", request_id=ip_request)
request = context(result, "EDLManager.Request") or {}
check("request-get (approved)", request.get("Status") == "approved" and request.get("EntryID") == entry.get("ID"), result)

result = run("edl-manager-request-approve", request_id=ip_request)
check("second approval is a conflict", result["Type"] == ERROR_ENTRY and "409 (conflict)" in result.get("Contents", ""), result)

firewall_fetch()
result = run("edl-manager-entry-list", type="ip")
check("entry-list", [e["Entry"] for e in context(result, "EDLManager.Entry") or []] == ["203.0.113.10"], result)

result = run("edl-manager-entry-get", entry_id=entry.get("ID"))
check("entry-get", (context(result, "EDLManager.Entry") or {}).get("RequestID") == ip_request, result)

result = run("edl-manager-metrics-get", days=30)
metrics = context(result, "EDLManager.Metrics") or {}
check("metrics-get counts the firewall fetch", metrics.get("Firewalls", {}).get("Total") == 1, metrics)
check("metrics-get measures time to enforcement", metrics.get("TimeToEnforcement", {}).get("Count") == 1, metrics)

result = run("edl-manager-entry-remove", entry_id=entry.get("ID"), reason="Takedown confirmed")
check("entry-remove", (context(result, "EDLManager.Entry") or {}).get("Status") == "deleted", result)

print(f"{failures} check(s) failed" if failures else "All checks passed")  # noqa: T201
sys.exit(1 if failures else 0)
