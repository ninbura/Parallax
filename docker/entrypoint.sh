#!/bin/sh
# Parallax container entrypoint.
#   run       on first start import the configuration, check the host
#             (`parallax doctor`), create the server key, start tailscaled,
#             then become `parallax daemon`: it applies, serves DNS and the
#             HTTPS proxy, applies every saved change, repairs drift and backs
#             up when due. SIGHUP re-applies; SIGTERM takes the gateway down.
#   <other>   pass through to the parallax binary (e.g. `doctor`, `peer add ...`),
#             which talks to the running daemon over its socket
set -eu

# The database is the configuration. CONFIG is only read once, on the first
# start, to fill an empty database.
CONFIG="${PARALLAX_CONFIG:-/etc/parallax/parallax.toml}"
export PARALLAX_DB="${PARALLAX_DB:-/var/lib/parallax/parallax.db}"
OUT="${PARALLAX_OUT:-/var/lib/parallax}"

# --- first start: import the TOML, then rename it ----------------------------
# Renamed so nobody keeps editing a file Parallax no longer reads. `--if-empty`
# decides inside the database's write transaction, so a database left empty by
# an interrupted import is filled on the next start, and one that already
# holds a configuration is never overwritten.
first_start() {
    if [ ! -f "$CONFIG" ]; then
        return 0   # `parallax doctor` says if the database holds nothing either
    fi
    out="$(parallax config import --if-empty "$CONFIG")"
    case "$out" in
        imported*)
            echo "parallax: $out"
            if mv "$CONFIG" "$CONFIG.imported" 2>/dev/null; then
                echo "parallax: renamed $CONFIG to $CONFIG.imported; from now on change the configuration with \`parallax config edit\`"
            else
                echo "parallax: warning: could not rename $CONFIG (read-only?); it is ignored from now on" >&2
            fi
            ;;
        *)
            echo "parallax: warning: $CONFIG is ignored; the configuration lives in $PARALLAX_DB (change it with \`parallax config edit\`)" >&2
            ;;
    esac
}

MODE="${1:-run}"
if [ "$MODE" != "run" ]; then
    exec parallax "$@"
fi

first_start

# --- startup checks: privileges, kernel features, tools, interfaces --------
if ! parallax doctor; then
    echo "parallax: not starting; fix the problems above (docs/setup.md explains each)" >&2
    exit 1
fi

# --- private key bootstrap -------------------------------------------------
# Creates the key and records its public half only when the key file is missing.
parallax keygen --if-missing --write-config

# --- tailscaled: always on; M2 logs it into Headscale as the subnet router -----
# --netfilter-mode=off is passed at `tailscale up` time (M2); tailscaled itself owns no rules.
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock \
    --tun=tailscale0 --port=41641 >/var/log/tailscaled.log 2>&1 &

# The daemon holds the database from here on; `docker exec parallax parallax ...`
# goes through its socket. tini (the image's init) forwards signals to it and
# reaps tailscaled if it dies.
exec parallax daemon -o "$OUT"
