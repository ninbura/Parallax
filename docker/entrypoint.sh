#!/bin/sh
# Parallax container entrypoint.
#   run       check the host (`parallax doctor`), apply the configuration,
#             start tailscaled and the HTTPS proxy, stay up; SIGHUP re-applies
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
    [ -f "$OUT/dnsmasq/dnsmasq.pid" ] && kill "$(cat "$OUT/dnsmasq/dnsmasq.pid")" 2>/dev/null || true
    kill "$TAILSCALED_PID" "${PROXY_PID:-}" "${SLEEP_PID:-}" 2>/dev/null || true
    nft delete table inet parallax 2>/dev/null || true
    ip link del "$(sed -n 's/^interface *= *"\(wg[0-9]*\)"/\1/p' "$CONFIG" | head -n1)" 2>/dev/null || true
    exit 0
}

reload() {
    echo "parallax: SIGHUP, re-applying"
    if apply; then
        # The proxy re-reads its routes (and certificates) on SIGHUP.
        kill -HUP "$PROXY_PID" 2>/dev/null || true
        echo "parallax: re-applied"
    else
        echo "parallax: re-apply failed; fix $CONFIG and send SIGHUP again" >&2
    fi
}

trap teardown TERM INT
trap reload HUP
apply
# After apply: the proxy listens on the gateway address, which wg0 now carries.
parallax -c "$CONFIG" proxy -o "$OUT" &
PROXY_PID=$!
echo "parallax: gateway up; send SIGHUP to re-apply after editing $CONFIG"
# A trapped signal makes `wait` return >128, which `set -e` would treat as fatal.
while :; do
    sleep 3600 &
    SLEEP_PID=$!
    wait "$SLEEP_PID" || true
    kill "$SLEEP_PID" 2>/dev/null || true
done
