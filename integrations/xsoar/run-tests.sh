#!/usr/bin/env bash
# Runs the XSOAR pack's unit tests in the Docker image Cortex XSOAR runs the
# integration in, with the content repo's pytest conftest (no warnings, no
# stdout). The network is off: tests use recorded API responses.
# Usage: integrations/xsoar/run-tests.sh <demisto/content checkout>
set -euo pipefail

content="$(cd "${1:?usage: $0 <demisto/content checkout>}" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
integration="$here/Packs/EDLManager/Integrations/EDLManager"
image="$(sed -n 's/^  dockerimage: //p' "$integration/EDLManager.yml")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -r "$integration/." "$work/pkg"
cp "$content/Tests/scripts/dev_envs/pytest/conftest.py" "$work/pkg/"
mkdir "$work/stubs"
: > "$work/stubs/CommonServerUserPython.py" # XSOAR injects an empty one at runtime

# Test tools only; the integration's own dependencies come from the image.
"${PYTHON:-python3}" -m pip install --quiet --target "$work/deps" pytest==8.3.5
"${PYTHON:-python3}" -m pip install --quiet --no-deps --target "$work/deps" requests-mock==1.12.1 pytest-mock==3.14.0

docker run --rm --network none \
    -v "$work/pkg:/work" -v "$work/deps:/deps:ro" -v "$work/stubs:/stubs:ro" \
    -v "$content/Packs/Base/Scripts/CommonServerPython:/csp:ro" \
    -v "$content/Packs/ApiModules/Scripts/DemistoClassApiModule:/dcam:ro" \
    -v "$content/Tests/demistomock:/dm:ro" \
    -e PYTHONPATH=/deps:/csp:/dcam:/dm:/stubs:/work -e PYTHONDONTWRITEBYTECODE=1 \
    -w /work "$image" python -m pytest -q -p no:cacheprovider EDLManager_test.py
