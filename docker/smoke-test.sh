#!/usr/bin/env bash
# Runs the image with the same hardening as compose.yaml and checks what an
# operator, a firewall, and an attacker would see.
# Usage: docker/smoke-test.sh <image>
# No "set -e": every check runs and reports, even after an earlier failure.
# shellcheck disable=SC2015  # "cond && pass || fail" is safe: pass only echoes.
set -uo pipefail

image="${1:?usage: $0 <image>}"
name="edl-smoke-$$"
port="${SMOKE_PORT:-18080}"
base="http://127.0.0.1:$port"
password="smoke-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
jar="$(mktemp)"
failures=0

cleanup() {
    docker rm -fv "$name" >/dev/null 2>&1 || true
    rm -f "$jar"
}
trap cleanup EXIT

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }
status() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }

expect_status() {
    local want="$1" path="$2" got
    got="$(status "$path")"
    if [[ "$got" == "$want" ]]; then pass "$path -> $got"; else fail "$path -> $got (want $want)"; fi
}

expect_blocked() {
    local path="$1" got
    got="$(status "$path")"
    if [[ "$got" == 403 || "$got" == 404 ]]; then pass "$path -> $got"; else fail "$path -> $got (want 403 or 404)"; fi
}

docker run -d --name "$name" -p "127.0.0.1:$port:8080" \
    --read-only --tmpfs /tmp --tmpfs /var/run/apache2 --tmpfs /var/lock/apache2 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -e EDL_ADMIN_PASSWORD="$password" \
    "$image" >/dev/null || exit 1

for _ in $(seq 1 30); do
    [[ "$(status /edl-files/ip_blocklist.txt)" == 200 ]] && break
    sleep 1
done

echo "== Firewall-facing blocklists"
expect_status 200 /edl-files/ip_blocklist.txt
expect_status 200 /edl-files/domain_blocklist.txt
expect_status 200 /edl-files/url_blocklist.txt
expect_status 403 /edl-files/

echo "== Internal files are not served"
expect_status 403 /data/users.json
expect_status 403 /data/audit_logs.json
expect_status 403 /config/config.php
expect_status 403 /includes/auth.php
for path in /user_setup.php /setup.php /test_index.php /debug.php /debug_okta.php \
            /docker/entrypoint.sh /README.md /.git/config /.gitignore; do
    expect_blocked "$path"
done

echo "== Response headers"
headers="$(curl -sI "$base/login.php")"
grep -qi '^x-content-type-options: nosniff' <<<"$headers" && pass "nosniff header" || fail "nosniff header missing"
grep -qi '^x-powered-by' <<<"$headers" && fail "X-Powered-By exposes PHP" || pass "no X-Powered-By"
grep -qi '^server: apache/' <<<"$headers" && fail "Server header exposes the Apache version" || pass "Server header has no version"
grep -i '^set-cookie' <<<"$headers" | grep -qi 'httponly' && pass "session cookie is HttpOnly" || fail "session cookie is not HttpOnly"

echo "== Accounts"
users="$(docker exec "$name" edl-users list)"
[[ "$(wc -l <<<"$users")" == 1 && "$users" == admin* ]] && pass "only the admin account exists" || fail "unexpected accounts: $users"

echo "== Login"
form_value() { grep -o "name=\"$1\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="//; s/"$//'; }
login() {
    curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code} %{redirect_url}' \
        --data-urlencode username=admin --data-urlencode "password=$1" --data-urlencode "csrf_token=$2" "$base/login.php"
}
expect_status 302 /index.php
token="$(curl -s -c "$jar" -b "$jar" "$base/login.php" | form_value csrf_token)"
got="$(login "$password" "")"
[[ "$got" == "200 " ]] && pass "login without a CSRF token is rejected" || fail "login without CSRF token -> $got"
got="$(login wrong-password "$token")"
[[ "$got" == "200 " ]] && pass "wrong password is rejected" || fail "wrong password -> $got"
got="$(login "$password" "$token")"
[[ "$got" == "302 $base/index.php" ]] && pass "admin login redirects to the dashboard" || fail "admin login -> $got"
got="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' "$base/index.php")"
[[ "$got" == 200 ]] && pass "dashboard loads after login" || fail "dashboard -> $got"

echo "== Submit, approve, publish"
token="$(curl -s -c "$jar" -b "$jar" "$base/pages/submit_request.php" | form_value csrf_token)"
curl -s -c "$jar" -b "$jar" -o /dev/null --data-urlencode "csrf_token=$token" \
    -d submission_type=individual -d entry=203.0.113.25 -d type=ip -d priority=high \
    -d servicenow_ticket=INC1234567 --data-urlencode "justification=Smoke test" \
    "$base/pages/submit_request.php"
approvals="$(curl -s -c "$jar" -b "$jar" "$base/pages/approvals.php")"
request_id="$(form_value request_id <<<"$approvals")"
[[ -n "$request_id" ]] && pass "submitted request is pending approval" || fail "no pending request after submit"
curl -s -c "$jar" -b "$jar" -o /dev/null --data-urlencode "csrf_token=$(form_value csrf_token <<<"$approvals")" \
    -d "request_id=$request_id" -d action=approve -d admin_comment=ok "$base/pages/approvals.php"
grep -qx '203.0.113.25' <(curl -s "$base/edl-files/ip_blocklist.txt") \
    && pass "approved IP is published in ip_blocklist.txt" || fail "approved IP missing from ip_blocklist.txt"

echo "== REST API"
json_get() {
    python3 -c 'import json, sys
d = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.isdigit() else d[k]
print(d)' "$1" 2>/dev/null
}
expect_status 200 /api/v1/health
expect_status 401 /api/v1/requests
expect_status 200 /api/v1/openapi.yaml
keys_page="$(curl -s -c "$jar" -b "$jar" "$base/pages/api_keys.php")"
curl -s -c "$jar" -b "$jar" -o /dev/null --data-urlencode "csrf_token=$(form_value csrf_token <<<"$keys_page")" \
    -d action=create -d name=smoke -d 'permissions[]=view' -d 'permissions[]=submit' -d 'permissions[]=approve' \
    "$base/pages/api_keys.php"
key="$(curl -s -c "$jar" -b "$jar" "$base/pages/api_keys.php" | grep -o 'edl_[0-9a-f]\{12\}_[A-Za-z0-9_-]\{43\}' | head -1)"
[[ -n "$key" ]] && pass "API key shown once after creating it" || fail "no API key shown after creating one"
api() { curl -s -H "Authorization: Bearer $key" -H 'Content-Type: application/json' "$@"; }
created="$(api -X POST -d '{"entry":"192.0.2.50","justification":"Smoke test","servicenow_ticket":"SIR1234567","priority":"critical"}' "$base/api/v1/requests")"
api_request="$(json_get data.created.0.id <<<"$created")"
[[ -n "$api_request" ]] && pass "API submission creates a pending request" || fail "API submission failed: $created"
got="$(api -o /dev/null -w '%{http_code}' -X POST -d '{"comment":"ok"}' "$base/api/v1/requests/$api_request/approve")"
[[ "$got" == 200 ]] && pass "API approval" || fail "API approval -> $got"
grep -qx '192.0.2.50' <(curl -s -A smoke-firewall "$base/edl-files/ip_blocklist.txt") \
    && pass "API-approved IP is published" || fail "API-approved IP missing from ip_blocklist.txt"
got="$(api "$base/api/v1/requests/$api_request" | json_get data.status)"
[[ "$got" == approved ]] && pass "request status reads approved" || fail "request status: $got"
entry_id="$(api "$base/api/v1/entries?q=192.0.2.50" | json_get data.0.id)"
got="$(api -o /dev/null -w '%{http_code}' -X DELETE "$base/api/v1/entries/$entry_id")"
[[ "$got" == 403 ]] && pass "key without \"remove\" can't delete entries" || fail "DELETE without permission -> $got"
curl -sI "$base/edl-files/ip_blocklist.txt" | grep -qi '^set-cookie' \
    && fail "list download sets a session cookie" || pass "list downloads set no cookie"

echo "== Impact metrics"
metrics="$(api "$base/api/v1/metrics?days=1")"
[[ "$(json_get data.firewalls.tracking <<<"$metrics")" == True ]] && pass "list fetches are tracked" || fail "fetch tracking is off"
grep -q 'smoke-firewall' <<<"$metrics" && pass "firewall client listed by user agent" || fail "firewall client missing from metrics"
got="$(json_get data.time_to_enforcement.count <<<"$metrics")"
[[ "$got" =~ ^[0-9]+$ && "$got" -ge 2 ]] && pass "time to enforcement measured for both approvals" || fail "time to enforcement count: $got"
got="$(curl -s -b "$jar" -o /dev/null -w '%{http_code}' "$base/pages/metrics.php")"
[[ "$got" == 200 ]] && pass "Impact page loads" || fail "Impact page -> $got"
got="$(curl -s -b "$jar" "$base/pages/metrics.php?days=7&format=json" | json_get window.days)"
[[ "$got" == 7 ]] && pass "Impact JSON export" || fail "Impact JSON export: $got"

if (( failures > 0 )); then
    echo "== Container logs"
    docker logs "$name" 2>&1 | tail -50
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
