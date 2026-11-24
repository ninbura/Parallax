#!/bin/sh
# Parallax container entrypoint.
#   run       on first start import the configuration, check the host
#             (`parallax doctor`), apply, start tailscaled, the DNS server and
#             the HTTPS proxy, stay up; SIGHUP re-applies
#   <other>   pass through to the parallax binary (e.g. `doctor`, `peer add ...`)
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
TAILSCALED_PID=$!

# The WireGuard interface the last successful apply configured, for teardown:
# apply writes wireguard/<interface>.conf. Not read from the database, which
# may already hold an edit that isn't applied yet.
WG_IF=
apply() {
    parallax apply -o "$OUT" || return 1
    # Newest: a renamed interface leaves its old file behind.
    conf="$(ls -t "$OUT"/wireguard/*.conf 2>/dev/null | head -n1)"
    if [ -n "$conf" ]; then
        WG_IF="$(basename "$conf" .conf)"
    fi
}

teardown() {
    echo "parallax: shutting down"
    kill "$TAILSCALED_PID" ${DNS_PID:-} ${PROXY_PID:-} 2>/dev/null || true
    nft delete table inet parallax 2>/dev/null || true
    [ -n "$WG_IF" ] && ip link del "$WG_IF" 2>/dev/null || true
    exit "${1:-0}"
}

reload() {
    echo "parallax: SIGHUP, re-applying"
    if apply; then
        # The DNS server and the proxy re-read their routes on SIGHUP. If one
        # can't, it refuses everything until a reload succeeds rather than
        # keep the old grants. Unset during the first apply: both start after it.
        for pid in ${DNS_PID:-} ${PROXY_PID:-}; do
            kill -HUP "$pid" 2>/dev/null || true
        done
        echo "parallax: re-applied"
    else
        echo "parallax: re-apply failed; fix the configuration (\`parallax config edit\`) and send SIGHUP again" >&2
    fi
}

# Running, and not a zombie: a child that exited but isn't reaped yet still
# answers `kill -0`, and when the shell reaps it varies between shells.
alive() {
    kill -0 "$1" 2>/dev/null && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

trap teardown TERM INT
trap reload HUP
apply
# After apply: both listen on the gateway address, which wg0 now carries.
parallax dns -o "$OUT" &
DNS_PID=$!
parallax proxy -o "$OUT" &
PROXY_PID=$!
# Most failures (port taken, unreadable CA bundle) happen at once.
sleep 1
for name_pid in "DNS server:$DNS_PID" "HTTPS proxy:$PROXY_PID"; do
    if ! alive "${name_pid##*:}"; then
        echo "parallax: the ${name_pid%:*} did not start; see above" >&2
        teardown 1
    fi
done
echo "parallax: gateway up; send SIGHUP to re-apply after changing the configuration"
# Wait on both. A trapped signal makes `wait` return >128 while they still
# run (and `set -e` would treat that as fatal). If either exits, so does the
# container, and Docker's restart policy takes over.
while :; do
    sleep 2 &
    wait $! || true
    for name_pid in "DNS server:$DNS_PID" "HTTPS proxy:$PROXY_PID"; do
        if ! alive "${name_pid##*:}"; then
            echo "parallax: the ${name_pid%:*} exited; stopping" >&2
            teardown 1
        fi
    done
done
