#!/bin/sh
# Engine entrypoint (H-F8 / D-024): the container starts as root only to make
# /data writable by the unprivileged `loom` user — volumes created by older
# (root) builds keep working across the upgrade — then drops privileges with
# setpriv before running anything. When started as a non-root user already
# (k8s runAsUser, `docker compose run --user ...`), it just execs.
# Nothing is printed to stdout: `python -m loom.schemas > file` must stay clean.
set -e
if [ "$(id -u)" = "0" ]; then
    if [ -d /data ]; then
        find /data -maxdepth 1 ! -uid 10001 -exec chown loom:loom {} + 2>/dev/null \
            || echo "loom-entrypoint: could not chown /data; continuing" >&2
    fi
    exec setpriv --reuid=loom --regid=loom --init-groups "$@"
fi
exec "$@"
