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
# Renamed so nobody keeps editing a file Parallax no longer reads.
first_start() {
    if [ -f "$PARALLAX_DB" ]; then
        if [ -f "$CONFIG" ]; then
            echo "parallax: warning: $CONFIG is ignored; the configuration lives in $PARALLAX_DB (change it with \`parallax config edit\`)" >&2
        fi
        return 0
    fi
    if [ ! -f "$CONFIG" ]; then
        echo "parallax: no configuration yet; put a parallax.toml at $CONFIG (start from example/parallax.toml) and start again" >&2
        return 1
    fi
    parallax config import "$CONFIG"
    if mv "$CONFIG" "$CONFIG.imported" 2>/dev/null; then
        echo "parallax: renamed $CONFIG to $CONFIG.imported; from now on change the configuration with \`parallax config edit\`"
    else
        echo "parallax: warning: could not rename $CONFIG (read-only?); it is ignored from now on" >&2
    fi
}

# The WireGuard interface, for teardown.
wg_interface() {
    parallax config export 2>/dev/null | sed -n 's/^interface *= *"\(wg[0-9]*\)"/\1/p' | head -n1
}

MODE="${1:-run}"
if [ "$MODE" != "run" ]; then
    if [ ! -f "$PARALLAX_DB" ] && [ -f "$CONFIG" ]; then
        first_start
    fi
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

apply() {
    parallax apply -o "$OUT"
}

teardown() {
    echo "parallax: shutting down"
    kill "$TAILSCALED_PID" ${DNS_PID:-} ${PROXY_PID:-} 2>/dev/null || true
    nft delete table inet parallax 2>/dev/null || true
    ip link del "$(wg_interface)" 2>/dev/null || true
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
