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
expect_status 302 /index.php
got="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code} %{redirect_url}' \
    --data-urlencode username=admin --data-urlencode "password=wrong-password" "$base/login.php")"
[[ "$got" == "200 " ]] && pass "wrong password is rejected" || fail "wrong password -> $got"
got="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code} %{redirect_url}' \
    --data-urlencode username=admin --data-urlencode "password=$password" "$base/login.php")"
[[ "$got" == "302 $base/index.php" ]] && pass "admin login redirects to the dashboard" || fail "admin login -> $got"
got="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' "$base/index.php")"
[[ "$got" == 200 ]] && pass "dashboard loads after login" || fail "dashboard -> $got"

echo "== Submit, approve, publish"
form_value() { grep -o "name=\"$1\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="//; s/"$//'; }
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

if (( failures > 0 )); then
    echo "== Container logs"
    docker logs "$name" 2>&1 | tail -50
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
