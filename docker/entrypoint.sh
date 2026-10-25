#!/bin/sh
# Container entrypoint: prepares the data volumes, then hands off to the
# official PHP image's entrypoint.
set -eu

DATA_DIR="${EDL_DATA_DIR:-/var/lib/edl-manager}"
LISTS_DIR="/var/www/html/edl-files"

for dir in "$DATA_DIR" "$LISTS_DIR"; do
    if [ ! -w "$dir" ]; then
        echo "edl-manager: $dir is not writable by uid $(id -u)." >&2
        echo "edl-manager: use a named volume, or chown a bind-mounted directory to uid 33 (www-data)." >&2
        exit 1
    fi
done

# Firewalls start polling before anything is approved; serve empty lists
# instead of 404s.
for list in ip_blocklist.txt domain_blocklist.txt url_blocklist.txt; do
    [ -e "$LISTS_DIR/$list" ] || : > "$LISTS_DIR/$list"
done

# A fresh install has no accounts, and the app's only way to create them is
# user_setup.php, which has no authentication and is left out of the image.
# Create the admin account before Apache starts.
if [ "${1:-}" = "apache2-foreground" ]; then
    edl-users init-admin
fi

exec docker-php-entrypoint "$@"
