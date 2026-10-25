#!/usr/bin/env bash
# Starts EDL Manager, creates an API key through the web UI, and runs every
# integration command against it from the Cortex XSOAR runtime image.
# Usage: integrations/xsoar/e2e.sh <EDL Manager image> <demisto/content checkout>
set -euo pipefail

edl_image="${1:?usage: $0 <EDL Manager image> <demisto/content checkout>}"
content="$(cd "${2:?usage: $0 <EDL Manager image> <demisto/content checkout>}" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
integration="$here/Packs/EDLManager/Integrations/EDLManager"
xsoar_image="$(sed -n 's/^  dockerimage: //p' "$integration/EDLManager.yml")"
name="edl-xsoar-e2e-$$"
port="${E2E_PORT:-18097}"
base="http://127.0.0.1:$port"
password="e2e-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
work="$(mktemp -d)"

cleanup() {
    docker rm -fv "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

docker run -d --name "$name" -p "127.0.0.1:$port:8080" -e EDL_ADMIN_PASSWORD="$password" "$edl_image" >/dev/null
for _ in $(seq 1 30); do
    curl -sf -o /dev/null "$base/api/v1/health" && break
    sleep 1
done

# Sign in and create a key on the API Keys page, as an admin would.
jar="$work/cookies"
form_value() { grep -o "name=\"$1\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="//; s/"$//'; }
token="$(curl -s -c "$jar" -b "$jar" "$base/login.php" | form_value csrf_token)"
curl -s -c "$jar" -b "$jar" -o /dev/null --data-urlencode username=admin \
    --data-urlencode "password=$password" --data-urlencode "csrf_token=$token" "$base/login.php"
token="$(curl -s -c "$jar" -b "$jar" "$base/pages/api_keys.php" | form_value csrf_token)"
curl -s -c "$jar" -b "$jar" -o /dev/null --data-urlencode "csrf_token=$token" -d action=create -d name=xsoar-e2e \
    -d 'permissions[]=view' -d 'permissions[]=submit' -d 'permissions[]=approve' -d 'permissions[]=remove' \
    "$base/pages/api_keys.php"
key="$(curl -s -c "$jar" -b "$jar" "$base/pages/api_keys.php" | grep -o 'edl_[0-9a-f]\{12\}_[A-Za-z0-9_-]\{43\}' | head -1)"
[[ -n "$key" ]] || { echo "Could not create an API key"; docker logs "$name" 2>&1 | tail -20; exit 1; }

mkdir "$work/stubs"
: > "$work/stubs/CommonServerUserPython.py" # XSOAR injects an empty one at runtime
docker run --rm --network host \
    -v "$integration:/integration:ro" -v "$here/e2e.py:/e2e.py:ro" -v "$work/stubs:/stubs:ro" \
    -v "$content/Packs/Base/Scripts/CommonServerPython:/csp:ro" \
    -v "$content/Packs/ApiModules/Scripts/DemistoClassApiModule:/dcam:ro" \
    -v "$content/Tests/demistomock:/dm:ro" \
    -e PYTHONPATH=/csp:/dcam:/dm:/stubs:/integration -e PYTHONDONTWRITEBYTECODE=1 \
    "$xsoar_image" python /e2e.py "$base" "$key"
