#!/usr/bin/env bash
# Runs all three benchmarks and writes their JSON to bench/results/.
# Usage: bench/run.sh [EDL Manager image]   (default: builds edl-manager:bench)
# Needs Docker, PHP 8 and Python 3. Takes about 15 minutes.
set -euo pipefail
shopt -s inherit_errexit

here="$(cd "$(dirname "$0")" && pwd)"
results="$here/results"
image="${1:-}"
mkdir -p "$results"

if [[ -z "$image" ]]; then
    image=edl-manager:bench
    docker build -q -t "$image" "$here/.." >/dev/null
fi

# The container as compose.yaml runs it, on a fixed port. Prints the API key.
start() {
    local name="$1" port="$2" entries="$3"
    docker rm -fv "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" -p "127.0.0.1:$port:8080" \
        --read-only --tmpfs /tmp --tmpfs /var/run/apache2 --tmpfs /var/lock/apache2 \
        --cap-drop ALL --security-opt no-new-privileges:true \
        -e EDL_ADMIN_PASSWORD="bench-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" "$image" >/dev/null
    for _ in $(seq 1 30); do
        curl -sf -o /dev/null "http://127.0.0.1:$port/api/v1/health" && break
        sleep 1
    done
    # docker cp can't write into a read-only container, even its tmpfs /tmp.
    docker exec -i "$name" sh -c 'cat > /tmp/entries.php' < "$here/entries.php"
    docker exec -i "$name" sh -c 'cat > /tmp/seed.php' < "$here/seed.php"
    docker exec -e N="$entries" "$name" php /tmp/seed.php
}
trap 'docker rm -fv edl-bench-http edl-bench-accuracy >/dev/null 2>&1 || true' EXIT

echo "1/3 publish, approve, and submit time by list size"
php "$here/publish.php" 1000 10000 50000 100000 > "$results/publish.json"

echo "2/3 list downloads and API latency (10,000 entries loaded)"
key="$(start edl-bench-http 18101 10000)"
python3 "$here/http_bench.py" http://127.0.0.1:18101 "$key" 10000 > "$results/http.json"
docker rm -fv edl-bench-http >/dev/null

echo "3/3 time-to-enforcement accuracy (about 5 minutes)"
key="$(start edl-bench-accuracy 18102 0)"
python3 "$here/enforcement.py" http://127.0.0.1:18102 "$key" 24 20 3 > "$results/enforcement.json"

python3 - "$results/environment.json" "$image" <<'EOF'
import json, os, platform, subprocess, sys
cpu = next((line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo") if line.startswith("model name")), platform.processor())
mem_gb = round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1)
docker = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True).stdout.strip()
php = subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True).stdout.strip()
json.dump({"cpu": cpu, "vcpus": os.cpu_count(), "memory_gb": mem_gb, "kernel": platform.release(),
           "docker": docker, "host_php": php, "python": platform.python_version(), "image": sys.argv[2]},
          open(sys.argv[1], "w"), indent=2)
EOF
echo "Results in $results"
