#!/bin/sh
# Parallax container entrypoint.
#   run       check the host (`parallax doctor`), apply the configuration,
#             start tailscaled, the DNS server and the HTTPS proxy, stay up;
#             SIGHUP re-applies
#   <other>   pass through to the parallax binary (e.g. `doctor`, `peer add ...`)
set -eu

CONFIG="${PARALLAX_CONFIG:-/etc/parallax/parallax.toml}"
OUT="${PARALLAX_OUT:-/var/lib/parallax}"

MODE="${1:-run}"
if [ "$MODE" != "run" ]; then
    exec parallax -c "$CONFIG" "$@"
fi

# --- startup checks: privileges, kernel features, tools, interfaces --------
if ! parallax -c "$CONFIG" doctor; then
    echo "parallax: not starting; fix the problems above (docs/setup.md explains each)" >&2
    exit 1
fi

# --- private key bootstrap -------------------------------------------------
KEYFILE="$(sed -n 's/^private_key_file *= *"\(.*\)"/\1/p' "$CONFIG" | head -n1)"
KEYFILE="${KEYFILE:-/etc/parallax/wg-server.key}"
if [ ! -f "$KEYFILE" ]; then
    echo "parallax: no server key at $KEYFILE, creating one and recording its public key"
    parallax -c "$CONFIG" keygen --write-config
fi

# --- tailscaled: always on; M2 logs it into Headscale as the subnet router -----
# --netfilter-mode=off is passed at `tailscale up` time (M2); tailscaled itself owns no rules.
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock \
    --tun=tailscale0 --port=41641 >/var/log/tailscaled.log 2>&1 &
TAILSCALED_PID=$!

apply() {
    parallax -c "$CONFIG" apply -o "$OUT"
}

teardown() {
    echo "parallax: shutting down"
    kill "$TAILSCALED_PID" ${DNS_PID:-} ${PROXY_PID:-} 2>/dev/null || true
    nft delete table inet parallax 2>/dev/null || true
    ip link del "$(sed -n 's/^interface *= *"\(wg[0-9]*\)"/\1/p' "$CONFIG" | head -n1)" 2>/dev/null || true
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
        echo "parallax: re-apply failed; fix $CONFIG and send SIGHUP again" >&2
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
parallax -c "$CONFIG" dns -o "$OUT" &
DNS_PID=$!
parallax -c "$CONFIG" proxy -o "$OUT" &
PROXY_PID=$!
# Most failures (port taken, unreadable CA bundle) happen at once.
sleep 1
for name_pid in "DNS server:$DNS_PID" "HTTPS proxy:$PROXY_PID"; do
    if ! alive "${name_pid##*:}"; then
        echo "parallax: the ${name_pid%:*} did not start; see above" >&2
        teardown 1
    fi
done
echo "parallax: gateway up; send SIGHUP to re-apply after editing $CONFIG"
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
