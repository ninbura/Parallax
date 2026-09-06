#!/bin/sh
# Parallax container entrypoint.
#   run       apply the configuration, start tailscaled, stay up; SIGHUP re-applies
#   <other>   pass through to the parallax binary (e.g. `peer add ...`)
set -eu

CONFIG="${PARALLAX_CONFIG:-/etc/parallax/parallax.toml}"
OUT="${PARALLAX_OUT:-/var/lib/parallax}"

if [ "${1:-run}" != "run" ]; then
    exec parallax -c "$CONFIG" "$@"
fi

fail() { echo "parallax: $*" >&2; exit 1; }

# --- startup checks: fail loudly, naming what is missing ------------------
[ -f "$CONFIG" ] || fail "no configuration at $CONFIG (mount your parallax.toml into /etc/parallax)"
command -v nft >/dev/null || fail "nft is missing from the image"
command -v wg >/dev/null || fail "wg is missing from the image"
command -v dnsmasq >/dev/null || fail "dnsmasq is missing from the image"
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] \
    || fail "net.ipv4.ip_forward is 0 on the host; set 'net.ipv4.ip_forward = 1' in /etc/sysctl.d and reload (the container shares the host network namespace)"
if ! ip link add parallax-probe type wireguard 2>/dev/null; then
    fail "cannot create a WireGuard interface: the host kernel lacks the wireguard module (modprobe wireguard on the host, or use a kernel >= 5.6)"
fi
ip link del parallax-probe
if ! nft -c -f - <<'NFT' 2>/dev/null
table inet parallax_probe {
    chain pre { type nat hook prerouting priority dstnat; ip daddr 192.0.2.0/24 dnat ip prefix to ip daddr map { 192.0.2.0/24 : 198.51.100.0/24 } }
}
NFT
then
    fail "the kernel or nft rejects NETMAP (prefix nat); needs nftables >= 0.9.4 and kernel nf_nat with prefix mapping"
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
    kill "$TAILSCALED_PID" 2>/dev/null || true
    nft delete table inet parallax 2>/dev/null || true
    ip link del "$(sed -n 's/^interface *= *"\(wg[0-9]*\)"/\1/p' "$CONFIG" | head -n1)" 2>/dev/null || true
    exit 0
}

trap teardown TERM INT
trap apply HUP
apply
echo "parallax: gateway up; send SIGHUP to re-apply after editing $CONFIG"
while :; do
    wait "$TAILSCALED_PID" 2>/dev/null || true
    sleep 3600 &
    wait $!
done
