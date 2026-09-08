#!/usr/bin/env bash
# Parallax M1 integration test on Linux network namespaces. Needs root, and:
# nft, wg, ip, dnsmasq, dig, curl, python3, and the parallax binary (PARALLAX=...).
#
# Topology (every namespace is fresh):
#   home    192.168.1.5   "Immich" host + home DNS (immich.mydomain.com -> 192.168.1.5)
#   gw      eth0 192.168.1.1 (home LAN), wan0 203.0.113.1, runs the real `parallax apply`
#   client  wan0 203.0.113.2 -> gw; lan0 192.168.1.10 on a *foreign* LAN with the
#           same prefix as home; WireGuard interfaces wgp (personal) and wgf (family)
#   foreign 192.168.1.5   the foreign host (same address as home's) + foreign DNS
#
# Assertions map to the handoff: (a) mapped virtual IP lands on the real host,
# (b) shim answers in virtual space, (c) guest reaches only its grant even with
# 0.0.0.0/0 AllowedIPs, (d) reapply is idempotent, (e) raw mapped access without
# the shim, (f) colliding-guest-network with split DNS.
set -euo pipefail

PARALLAX="${PARALLAX:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/parallax}"
[ -x "$PARALLAX" ] || { echo "parallax binary not found at $PARALLAX (cargo build first)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for t in nft wg ip dnsmasq dig curl python3; do command -v $t >/dev/null || { echo "missing $t"; exit 2; }; done

WORK=$(mktemp -d /tmp/parallax-it.XXXXXX)
PIDS=()
cleanup() {
    set +e
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    for ns in home gw client foreign; do ip netns del $ns 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }
inns() { ip netns exec "$@"; }

# ---------------------------------------------------------------- topology
for ns in home gw client foreign; do ip netns add $ns; inns $ns ip link set lo up; done
ip link add eth0 netns gw type veth peer name lan0 netns home
ip link add wan0 netns gw type veth peer name wan0 netns client
ip link add lan0 netns client type veth peer name lan0 netns foreign
inns gw ip addr add 192.168.1.1/24 dev eth0;   inns gw ip link set eth0 up
inns gw ip addr add 203.0.113.1/24 dev wan0;   inns gw ip link set wan0 up
inns home ip addr add 192.168.1.5/24 dev lan0; inns home ip link set lan0 up
inns home ip route add 10.8.0.0/16 via 192.168.1.1      # the static route the docs demand
inns home ip route add 100.64.0.0/10 via 192.168.1.1
inns client ip addr add 203.0.113.2/24 dev wan0; inns client ip link set wan0 up
inns client ip addr add 192.168.1.10/24 dev lan0; inns client ip link set lan0 up
inns foreign ip addr add 192.168.1.5/24 dev lan0; inns foreign ip link set lan0 up
inns gw sysctl -qw net.ipv4.ip_forward=1

# ---------------------------------------------------------------- services
serve() { # ns, port, body
    inns "$1" python3 - "$2" "$3" <<'PY' &
import sys, http.server
port, body = int(sys.argv[1]), sys.argv[2].encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", port), H).serve_forever()
PY
    PIDS+=($!)
}
serve home 443 home-immich
serve home 8080 home-other
serve gw 9090 gw-self
serve gw 9091 gw-hidden
serve foreign 443 foreign-immich
# Home DNS: authoritative-ish answers for mydomain.com; foreign DNS for hisdomain.com.
inns home dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
    --address=/immich.mydomain.com/192.168.1.5 --address=/other.mydomain.com/192.168.1.7 >/dev/null 2>&1 &
PIDS+=($!)
inns foreign dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
    --address=/immich.hisdomain.com/192.168.1.5 >/dev/null 2>&1 &
PIDS+=($!)
sleep 1

# ---------------------------------------------------------------- gateway
cat > "$WORK/parallax.toml" <<TOML
[server.wireguard]
supernet = "10.8.0.0/16"
endpoint = "203.0.113.1:51820"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private_key_file = "$WORK/wg-server.key"
[server.firewall]
docker_coexistence = false
[[network]]
name = "home"
interface = "eth0"
gateway_address = "192.168.1.1"
subnet = "192.168.1.0/24"
mapped_to = "192.168.240.0/24"
upstream_dns = ["192.168.1.5"]
domains = ["mydomain.com"]
[[service]]
name = "immich"
host = "192.168.1.5"
port = 443
nginx_vhost = true
[[service]]
name = "gwapp"
host = "192.168.1.1"
port = 9090
[[template]]
name = "personal"
grants = [{ kind = "all_networks" }]
[template.wireguard]
pool = "10.8.1.0/24"
[template.headscale]
user = "tester"
[[template]]
name = "family"
grants = [{ kind = "service", name = "immich" }, { kind = "service", name = "gwapp" }]
[template.wireguard]
pool = "10.8.2.0/24"
[template.headscale]
tag = "tag:family"
[template.dns]
wireguard = "tunnel_wide"
[template.client]
allowed_ips = "grants_only"
TOML
P="$PARALLAX -c $WORK/parallax.toml"
$P keygen --write-config >/dev/null
$P peer add laptop --template personal --keep-private-key --platform linux > "$WORK/laptop.conf" 2>/dev/null
$P peer add guest --template family --keep-private-key --platform mobile > "$WORK/guest.conf" 2>/dev/null
$P validate >/dev/null
inns gw $P apply -o "$WORK/out" >/dev/null
GW_PUB=$(sed -n 's/^public_key = "\(.*\)"/\1/p' "$WORK/parallax.toml")
[ -f "$WORK/out/dnsmasq/dnsmasq.pid" ] || fail "shim did not start"

# ---------------------------------------------------------------- clients
# Deliberately widen AllowedIPs to 0.0.0.0/0 (minus the foreign LAN, which stays local):
# the client config is never an enforcement point.
mkclient() { # iface, conf, addr, wan-side
    local key
    key=$(sed -n 's/^PrivateKey = //p' "$2")
    inns client ip link add "$1" type wireguard
    inns client ip addr add "$3/32" dev "$1"
    inns client wg set "$1" private-key <(echo "$key") peer "$GW_PUB" endpoint 203.0.113.1:51820 \
        allowed-ips 0.0.0.0/0 persistent-keepalive 5
    inns client ip link set "$1" up
}
mkclient wgp "$WORK/laptop.conf" 10.8.1.1
mkclient wgf "$WORK/guest.conf" 10.8.2.1
# Split tunnel routes: virtual range + shim through the tunnel, foreign LAN stays on lan0.
inns client ip route add 192.168.240.0/24 dev wgp src 10.8.1.1
inns client ip route add 10.8.0.1/32 dev wgp src 10.8.1.1
# The guest uses a separate routing table so both tunnels can coexist in one namespace.
inns client ip rule add from 10.8.2.1 table 200
inns client ip route add 192.168.240.0/24 dev wgf table 200
inns client ip route add 10.8.0.1/32 dev wgf table 200
sleep 1

curl_as() { # src, url  -> body or "BLOCKED"
    inns client curl -s -m 3 --interface "$1" "$2" || echo BLOCKED
}

# (a) mapped virtual IP lands on the real host
[ "$(curl_as 10.8.1.1 http://192.168.240.5:8080/)" = home-other ] || fail "(a) personal -> 192.168.240.5:8080"
[ "$(curl_as 10.8.1.1 http://192.168.240.5:443/)" = home-immich ] || fail "(a) personal -> 192.168.240.5:443"
[ "$(curl_as 10.8.1.1 http://192.168.240.1:9090/)" = gw-self ] || fail "(a) personal -> service on the gateway host"
pass "(a) personal peer reaches the mapped virtual address on the real host and on the gateway host"

# (b) shim answers in virtual space
ANS=$(inns client dig +short -b 10.8.1.1 @10.8.0.1 immich.mydomain.com)
[ "$ANS" = 192.168.240.5 ] || fail "(b) shim answered '$ANS'"
pass "(b) shim rewrites immich.mydomain.com to 192.168.240.5"

# (c) guest: granted host:port works, everything else is dropped despite 0.0.0.0/0
[ "$(curl_as 10.8.2.1 http://192.168.240.5:443/)" = home-immich ] || fail "(c) guest -> immich"
[ "$(curl_as 10.8.2.1 http://192.168.240.5:8080/)" = BLOCKED ] || fail "(c) guest reached a non-granted port"
[ "$(curl_as 10.8.2.1 http://192.168.240.1:9090/)" = gw-self ] || fail "(c) guest -> granted service on the gateway host"
[ "$(curl_as 10.8.2.1 http://192.168.240.1:9091/)" = BLOCKED ] || fail "(c) guest reached a non-granted port on the gateway host"
[ "$(curl_as 10.8.2.1 http://192.168.240.1:8080/)" = BLOCKED ] || fail "(c) guest reached the gateway LAN address"
ANS=$(inns client dig +short +time=1 +tries=1 -b 10.8.2.1 @10.8.0.1 immich.mydomain.com || true)
[ "$ANS" = 192.168.240.5 ] || fail "(c) guest could not use the shim (tunnel-wide DNS): '$ANS'"
pass "(c) guest reaches only its granted host:port; wider AllowedIPs change nothing"

# (d) reapply is idempotent
inns gw nft list table inet parallax > "$WORK/nft1"; inns gw wg showconf wg0 > "$WORK/wg1"
inns gw $P apply -o "$WORK/out" >/dev/null
inns gw nft list table inet parallax > "$WORK/nft2"; inns gw wg showconf wg0 > "$WORK/wg2"
diff -q "$WORK/nft1" "$WORK/nft2" >/dev/null || fail "(d) nft ruleset changed on reapply"
diff -q "$WORK/wg1" "$WORK/wg2" >/dev/null || fail "(d) wg config changed on reapply"
[ "$(curl_as 10.8.1.1 http://192.168.240.5:8080/)" = home-other ] || fail "(d) traffic broken after reapply"
pass "(d) reapply is idempotent"

# (e) raw mapped IP access with the shim stopped
kill "$(cat "$WORK/out/dnsmasq/dnsmasq.pid")"; sleep 0.5
[ "$(curl_as 10.8.1.1 http://192.168.240.5:8080/)" = home-other ] || fail "(e) mapped IP needs the shim"
pass "(e) raw mapped IP works with the shim stopped"
inns gw $P apply -o "$WORK/out" >/dev/null   # bring the shim back

# (f) colliding guest network: same name pattern, both boxes at 192.168.1.5
FOREIGN=$(inns client dig +short @192.168.1.5 immich.hisdomain.com)   # via lan0, local resolver
[ "$FOREIGN" = 192.168.1.5 ] || fail "(f) foreign resolver answered '$FOREIGN'"
HOME_ANS=$(inns client dig +short -b 10.8.1.1 @10.8.0.1 immich.mydomain.com)
[ "$HOME_ANS" = 192.168.240.5 ] || fail "(f) home name via shim answered '$HOME_ANS'"
[ "$(inns client curl -s -m 3 --resolve immich.hisdomain.com:443:$FOREIGN http://immich.hisdomain.com:443/)" = foreign-immich ] \
    || fail "(f) immich.hisdomain.com did not reach the foreign box"
[ "$(inns client curl -s -m 3 --interface 10.8.1.1 --resolve immich.mydomain.com:443:$HOME_ANS http://immich.mydomain.com:443/)" = home-immich ] \
    || fail "(f) immich.mydomain.com did not reach the home box"
pass "(f) foreign 192.168.1.5 and home 192.168.240.5 are both reachable, names resolve to the right one"

echo "ALL PASS"
