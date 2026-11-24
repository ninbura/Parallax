#!/usr/bin/env bash
# Parallax integration test on Linux network namespaces. Needs root, and:
# nft, wg, ip, dnsmasq, dig, curl, openssl, ping, python3, and the parallax
# binary (PARALLAX=...).
#
# Topology (every namespace is fresh):
#   home    192.168.1.5   "nginx" (TLS, picks the site by Host: immich and a sibling
#           other.mydomain.com) + home DNS + plain HTTP on 8080 + an echo on 7000
#   gw      eth0 192.168.1.1 (home LAN), wan0 203.0.113.1 (clients), up0 (internet),
#           docker0 172.17.0.1 (a Docker bridge); runs `parallax apply`, `parallax dns`
#           and `parallax proxy`
#   client  wan0 203.0.113.2 -> gw; lan0 192.168.1.10 on a *foreign* LAN with the
#           same prefix as home; WireGuard interfaces wgp (personal), wgf (family)
#           and wgx (friend)
#   foreign 192.168.1.5   the foreign host (same address as home's) + foreign DNS
#   net     the internet: 9.9.9.9 (a public server and the public resolver) and
#           10.99.0.5 (a private subnet the router knows but Parallax doesn't, like
#           another VLAN)
#   ctr     172.17.0.2, a "container" behind the gateway's Docker bridge
#
# Templates: personal (all_networks + internet, public DNS), family (the proxied
# Immich, a service on the gateway host, two echo ports), friend (internet only).
#
# Assertions: (a) mapped virtual IP lands on the real host, (b) the DNS server
# answers in virtual space, (c) guest reaches only its grants even with 0.0.0.0/0
# AllowedIPs, (d) reapply is idempotent, (e) raw mapped access without DNS,
# (f) colliding guest network with split DNS, (g) the proxy: by name only, one
# hostname, Host/SNI/:authority checked, (h) internet means public addresses,
# (i) nothing else on the gateway, its Docker bridge or the public address,
# (j) IPv6 from a peer is dropped, (k) a revoked grant cuts open connections,
# (l) DNS answers each tier only its names, and no private address outside the
# configured networks, (m) large DNS answers.
set -euo pipefail

PARALLAX="${PARALLAX:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/parallax}"
[ -x "$PARALLAX" ] || { echo "parallax binary not found at $PARALLAX (cargo build first)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for t in nft wg ip dnsmasq dig curl openssl ping python3; do command -v $t >/dev/null || { echo "missing $t"; exit 2; }; done

NAMESPACES="home gw client foreign net ctr"
# Cleanup kills everything in these namespaces, so never adopt ones that already exist.
for ns in $NAMESPACES; do
    ip netns list | grep -q "^$ns\( \|$\)" && { echo "namespace $ns already exists; delete it first"; exit 2; }
done

WORK=$(mktemp -d /tmp/parallax-it.XXXXXX)
PIDS=()
cleanup() {
    set +e
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    # $! above is the backgrounded `inns` subshell, not the server it starts: kill
    # whatever still runs in each namespace, or they outlive the test and keep the
    # caller's stdout open.
    for ns in $NAMESPACES; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null
    done
    sleep 0.2
    for ns in $NAMESPACES; do ip netns del $ns 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*"
    [ -s "$WORK/proxy.log" ] && { echo "--- proxy log"; tail -20 "$WORK/proxy.log"; }
    [ -s "$WORK/dns.log" ] && { echo "--- dns log"; tail -20 "$WORK/dns.log"; }
    exit 1
}
inns() { ip netns exec "$@"; }

# ---------------------------------------------------------------- topology
for ns in $NAMESPACES; do ip netns add $ns; inns $ns ip link set lo up; done
ip link add eth0 netns gw type veth peer name lan0 netns home
ip link add wan0 netns gw type veth peer name wan0 netns client
ip link add lan0 netns client type veth peer name lan0 netns foreign
ip link add up0 netns gw type veth peer name up0 netns net
ip link add vethctr netns gw type veth peer name eth0 netns ctr
inns gw ip addr add 192.168.1.1/24 dev eth0;   inns gw ip link set eth0 up
inns gw ip addr add 203.0.113.1/24 dev wan0;   inns gw ip link set wan0 up
inns gw ip addr add 198.51.100.1/24 dev up0;   inns gw ip link set up0 up
inns gw ip route add default via 198.51.100.2
inns gw ip link add docker0 type bridge
inns gw ip addr add 172.17.0.1/16 dev docker0; inns gw ip link set docker0 up
inns gw ip link set vethctr master docker0 up
inns home ip addr add 192.168.1.5/24 dev lan0; inns home ip link set lan0 up
inns home ip route add 10.8.0.0/16 via 192.168.1.1      # the static route the docs demand
inns home ip route add 100.64.0.0/10 via 192.168.1.1
inns client ip addr add 203.0.113.2/24 dev wan0; inns client ip link set wan0 up
inns client ip addr add 192.168.1.10/24 dev lan0; inns client ip link set lan0 up
inns foreign ip addr add 192.168.1.5/24 dev lan0; inns foreign ip link set lan0 up
inns net ip addr add 198.51.100.2/24 dev up0; inns net ip link set up0 up
inns net ip addr add 9.9.9.9/32 dev lo
inns net ip addr add 10.99.0.5/32 dev lo
inns ctr ip addr add 172.17.0.2/16 dev eth0; inns ctr ip link set eth0 up
inns ctr ip route add default via 172.17.0.1
inns gw sysctl -qw net.ipv4.ip_forward=1

# ---------------------------------------------------------------- certificates
# A throwaway CA; one certificate covers both sites on the home "nginx".
mkdir -p "$WORK/ca" "$WORK/certs/immich.mydomain.com"
(
    cd "$WORK/ca"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
        -subj /CN=parallax-test-ca -keyout ca.key -out ca.pem \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj /CN=immich.mydomain.com -keyout leaf.key -out leaf.csr
    printf 'subjectAltName=DNS:immich.mydomain.com,DNS:other.mydomain.com\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' > leaf.ext
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
        -extfile leaf.ext -out leaf.pem
) >/dev/null 2>&1 || fail "could not make the test certificates"
cat "$WORK/ca/leaf.pem" "$WORK/ca/ca.pem" > "$WORK/certs/immich.mydomain.com/fullchain.pem"
cp "$WORK/ca/leaf.key" "$WORK/certs/immich.mydomain.com/privkey.pem"
CA="$WORK/ca/ca.pem"

# ---------------------------------------------------------------- services
serve() { # ns, address, port, body
    inns "$1" python3 - "$2" "$3" "$4" <<'PY' &
import sys, http.server
addr, port, body = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer((addr, port), H).serve_forever()
PY
    PIDS+=($!)
}
echo_server() { # ns, port: echoes lines back, for connections held across an apply
    inns "$1" python3 - "$2" <<'PY' &
import sys, socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write(line)
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
    PIDS+=($!)
}
# The home "nginx": TLS on 443, the site picked by Host, like a box with several vhosts.
inns home python3 - "$WORK/ca/leaf.pem" "$WORK/ca/leaf.key" <<'PY' &
import sys, ssl, http.server
sites = {"immich.mydomain.com": b"home-immich", "other.mydomain.com": b"home-other-vhost"}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = sites.get((self.headers.get("Host") or "").split(":")[0], b"home-default")
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
PIDS+=($!)
serve home 0.0.0.0 8080 home-other
echo_server home 7000
serve gw 0.0.0.0 9090 gw-self
serve gw 0.0.0.0 9091 gw-hidden
echo_server gw 7000
serve foreign 0.0.0.0 443 foreign-immich
serve net 9.9.9.9 80 internet
serve net 10.99.0.5 80 vlan
serve ctr 0.0.0.0 80 container
# Home DNS: authoritative-ish answers for mydomain.com (big.mydomain.com has 40
# addresses, more than a 512-byte UDP answer holds); foreign DNS for hisdomain.com;
# a "public resolver" on the internet, with one name that points into private space.
BIG=()
for i in $(seq 10 49); do BIG+=(--host-record=big.mydomain.com,192.168.1.$i); done
inns home dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
    --address=/immich.mydomain.com/192.168.1.5 --address=/other.mydomain.com/192.168.1.5 \
    --host-record=vlan.mydomain.com,10.99.0.5 --host-record=vlan.mydomain.com,192.168.1.6 \
    "${BIG[@]}" >/dev/null 2>&1 &
PIDS+=($!)
inns net dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=9.9.9.9 --bind-interfaces \
    --address=/example.org/9.9.9.9 --address=/rebind.example.org/192.168.1.5 >/dev/null 2>&1 &
PIDS+=($!)
inns foreign dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
    --address=/immich.hisdomain.com/192.168.1.5 >/dev/null 2>&1 &
PIDS+=($!)
sleep 1

# ---------------------------------------------------------------- gateway
FAMILY_GRANTS='{ kind = "service", name = "immich" }, { kind = "service", name = "gwapp" }, { kind = "host_port", ip = "192.168.1.5", port = 7000 }, { kind = "host_port", ip = "192.168.1.1", port = 7000 }'
cat > "$WORK/parallax.toml" <<TOML
[server]
wan_interface = "up0"
[server.wireguard]
supernet = "10.8.0.0/16"
endpoint = "203.0.113.1:51820"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private_key_file = "$WORK/wg-server.key"
[server.dns]
public_resolver = "9.9.9.9"
[server.firewall]
docker_coexistence = false
[server.proxy]
certificates = "$WORK/certs"
upstream_ca = "$CA"
[[network]]
name = "home"
interface = "eth0"
gateway_address = "192.168.1.1"
subnet = "192.168.1.0/24"
mapped_to = "198.18.1.0/24"
upstream_dns = ["192.168.1.5"]
domains = ["mydomain.com"]
[[service]]
name = "immich"
host = "192.168.1.5"
port = 443
hostnames = ["immich.mydomain.com"]
[[service]]
name = "gwapp"
host = "192.168.1.1"
port = 9090
[[template]]
name = "personal"
grants = [{ kind = "all_networks" }, { kind = "internet" }]
[template.wireguard]
pool = "10.8.1.0/24"
[template.headscale]
user = "tester"
[template.dns]
public = true
[[template]]
name = "family"
grants = [$FAMILY_GRANTS]
[template.wireguard]
pool = "10.8.2.0/24"
[template.headscale]
tag = "tag:family"
[template.dns]
wireguard = "tunnel_wide"
[template.client]
allowed_ips = "grants_only"
[[template]]
name = "friend"
grants = [{ kind = "internet" }]
[template.wireguard]
pool = "10.8.3.0/24"
[template.headscale]
tag = "tag:friend"
[template.client]
allowed_ips = "full_tunnel"
TOML
P="$PARALLAX -c $WORK/parallax.toml"
$P keygen --write-config >/dev/null
$P peer add laptop --template personal --keep-private-key --platform linux > "$WORK/laptop.conf" 2>/dev/null
$P peer add guest --template family --keep-private-key --platform mobile > "$WORK/guest.conf" 2>/dev/null
$P peer add friend --template friend --keep-private-key --platform linux > "$WORK/friend.conf" 2>/dev/null
$P validate >/dev/null
inns gw $P doctor > "$WORK/doctor" || { cat "$WORK/doctor"; fail "doctor rejects the gateway namespace"; }
# Root in a user namespace (as under rootless Docker) must be refused. That root
# maps only uid 0, so run a copy it can reach (not one under someone's home).
cp "$PARALLAX" "$WORK/parallax"
if inns gw unshare -U -r "$WORK/parallax" -c "$WORK/parallax.toml" doctor > "$WORK/doctor-userns" 2>&1; then
    fail "doctor accepted a user namespace"
fi
grep -q "^FAIL  user namespace" "$WORK/doctor-userns" || fail "doctor did not name the user namespace"
pass "doctor passes on the gateway and refuses a user namespace"
inns gw $P apply -o "$WORK/out" >/dev/null
GW_PUB=$(sed -n 's/^public_key = "\(.*\)"/\1/p' "$WORK/parallax.toml")

# The DNS server and the proxy listen on the tunnel address, so they start once
# apply has made wg0, as the entrypoint does.
start() { # command, port
    inns gw sh -c 'echo $$ > "$1"; exec "$2" -c "$3" "$4" -o "$5"' sh \
        "$WORK/$1.pid" "$PARALLAX" "$WORK/parallax.toml" "$1" "$WORK/out" >> "$WORK/$1.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 50); do inns gw ss -Hltn "sport = :$2" | grep -q . && return 0; sleep 0.1; done
    fail "parallax $1 did not start"
}
start dns 53
start proxy 8443
# apply re-reads nothing in either; the entrypoint sends SIGHUP, so does this.
apply() { # [config]
    inns gw "$PARALLAX" -c "${1:-$WORK/parallax.toml}" apply -o "$WORK/out" >/dev/null
    kill -HUP "$(cat "$WORK/dns.pid")" "$(cat "$WORK/proxy.pid")"
    sleep 0.3
}

# ---------------------------------------------------------------- clients
# Deliberately widen AllowedIPs to 0.0.0.0/0 (minus the foreign LAN, which stays local):
# the client config is never an enforcement point.
mkclient() { # iface, conf, addr
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
mkclient wgx "$WORK/friend.conf" 10.8.3.1
# Split tunnel routes for the laptop: virtual range, the gateway and the test's internet hosts.
for dst in 198.18.1.0/24 10.8.0.1/32 9.9.9.9/32 10.99.0.5/32; do
    inns client ip route add $dst dev wgp src 10.8.1.1
done
# Guest and friend send everything through their tunnel (full tunnel), in their own
# routing tables so all three tunnels coexist in one namespace.
inns client ip rule add from 10.8.2.1 table 200
inns client ip route add default dev wgf table 200
inns client ip rule add from 10.8.3.1 table 201
inns client ip route add default dev wgx table 201
sleep 1

curl_as() { # src, [curl args...], url  -> body or "BLOCKED"
    local src=$1; shift
    inns client curl -s -m 3 --interface "$src" "$@" || echo BLOCKED
}
https_as() { # src, name, address, [curl args...]  -> body or "BLOCKED"
    local src=$1 name=$2 addr=$3; shift 3
    curl_as "$src" --cacert "$CA" --resolve "$name:443:$addr" "$@" "https://$name/"
}

LAPTOP=10.8.1.1 GUEST=10.8.2.1 FRIEND=10.8.3.1

# (a) mapped virtual IP lands on the real host
[ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] || fail "(a) personal -> 198.18.1.5:8080"
[ "$(https_as $LAPTOP immich.mydomain.com 198.18.1.5)" = home-immich ] || fail "(a) personal -> immich directly"
[ "$(https_as $LAPTOP other.mydomain.com 198.18.1.5)" = home-other-vhost ] || fail "(a) personal -> the sibling vhost directly"
[ "$(curl_as $LAPTOP http://198.18.1.1:9090/)" = gw-self ] || fail "(a) personal -> service on the gateway host"
pass "(a) personal peer reaches the mapped virtual address on the real host and on the gateway host"

# (b) DNS answers in virtual space
ANS=$(inns client dig +short -b $LAPTOP @10.8.0.1 immich.mydomain.com)
[ "$ANS" = 198.18.1.5 ] || fail "(b) DNS answered '$ANS'"
pass "(b) DNS rewrites immich.mydomain.com to 198.18.1.5"

# (c) guest: granted host:port works, everything else is dropped despite 0.0.0.0/0
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = BLOCKED ] || fail "(c) guest reached a non-granted port"
[ "$(curl_as $GUEST http://198.18.1.1:9090/)" = gw-self ] || fail "(c) guest -> granted service on the gateway host"
[ "$(curl_as $GUEST http://198.18.1.1:9091/)" = BLOCKED ] || fail "(c) guest reached a non-granted port on the gateway host"
[ "$(curl_as $GUEST http://198.18.1.1:8080/)" = BLOCKED ] || fail "(c) guest reached the gateway LAN address"
ANS=$(inns client dig +short +time=1 +tries=1 -b $GUEST @10.8.0.1 immich.mydomain.com || true)
[ "$ANS" = 198.18.1.5 ] || fail "(c) guest could not look up its granted name (tunnel-wide DNS): '$ANS'"
pass "(c) guest reaches only its granted host:port; wider AllowedIPs change nothing"

# (d) reapply is idempotent
inns gw nft list table inet parallax > "$WORK/nft1"; inns gw wg showconf wg0 > "$WORK/wg1"
apply
inns gw nft list table inet parallax > "$WORK/nft2"; inns gw wg showconf wg0 > "$WORK/wg2"
diff -q "$WORK/nft1" "$WORK/nft2" >/dev/null || fail "(d) nft ruleset changed on reapply"
diff -q "$WORK/wg1" "$WORK/wg2" >/dev/null || fail "(d) wg config changed on reapply"
[ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] || fail "(d) traffic broken after reapply"
pass "(d) reapply is idempotent"

# (e) raw mapped IP access with the DNS server stopped
kill "$(cat "$WORK/dns.pid")"; sleep 0.5
inns gw ss -Hlun 'sport = :53' | grep -q . && fail "(e) the DNS server is still running"
[ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] || fail "(e) mapped IP needs DNS"
pass "(e) raw mapped IP works with the DNS server stopped"
start dns 53

# (f) colliding guest network: same name pattern, both boxes at 192.168.1.5
FOREIGN=$(inns client dig +short @192.168.1.5 immich.hisdomain.com)   # via lan0, local resolver
[ "$FOREIGN" = 192.168.1.5 ] || fail "(f) foreign resolver answered '$FOREIGN'"
HOME_ANS=$(inns client dig +short -b $LAPTOP @10.8.0.1 immich.mydomain.com)
[ "$HOME_ANS" = 198.18.1.5 ] || fail "(f) home name via the gateway answered '$HOME_ANS'"
[ "$(inns client curl -s -m 3 --resolve immich.hisdomain.com:443:$FOREIGN http://immich.hisdomain.com:443/)" = foreign-immich ] \
    || fail "(f) immich.hisdomain.com did not reach the foreign box"
[ "$(https_as $LAPTOP immich.mydomain.com "$HOME_ANS")" = home-immich ] \
    || fail "(f) immich.mydomain.com did not reach the home box"
pass "(f) foreign 192.168.1.5 and home 198.18.1.5 are both reachable, names resolve to the right one"

# (g) the proxy: the guest reaches Immich by name, and nothing else on that box
ANS=$(inns client dig +short +time=1 +tries=1 -b $GUEST @10.8.0.1 immich.mydomain.com || true)
[ "$(https_as $GUEST immich.mydomain.com "$ANS" -w ' %{http_version}')" = "home-immich 2" ] \
    || fail "(g) guest -> immich by name through the proxy (HTTP/2)"
[ "$(https_as $GUEST immich.mydomain.com "$ANS" --http1.1)" = home-immich ] \
    || fail "(g) guest -> immich by name through the proxy (HTTP/1.1)"
[ "$(curl_as $GUEST -k https://198.18.1.5/)" = BLOCKED ] || fail "(g) guest reached the raw IP (no SNI)"
[ "$(https_as $GUEST other.mydomain.com 198.18.1.5)" = BLOCKED ] || fail "(g) guest reached the sibling vhost"
[ "$(https_as $GUEST other.mydomain.com 198.18.1.5 -k)" = BLOCKED ] || fail "(g) guest reached the sibling vhost (no verify)"
CODE=$(https_as $GUEST immich.mydomain.com 198.18.1.5 --http1.1 -H 'Host: other.mydomain.com' -o /dev/null -w '%{http_code}')
[ "$CODE" = 421 ] || fail "(g) Host != SNI answered '$CODE'"
CODE=$(https_as $GUEST immich.mydomain.com 198.18.1.5 --http2 -H 'Host: other.mydomain.com' -o /dev/null -w '%{http_code} %{http_version}')
[ "$CODE" = "421 2" ] || fail "(g) HTTP/2 :authority != SNI answered '$CODE'"
[ "$(curl_as $GUEST http://198.18.1.5:443/)" = BLOCKED ] || fail "(g) guest spoke plain HTTP to 443"
pass "(g) guest reaches immich by name through the proxy; raw IP, sibling vhost, Host and :authority mismatches fail"

# (h) internet: public addresses only, except for an all_networks template
[ "$(curl_as $FRIEND http://9.9.9.9/)" = internet ] || fail "(h) friend -> a public address"
[ "$(curl_as $FRIEND http://10.99.0.5/)" = BLOCKED ] || fail "(h) friend reached a private subnet through the router"
[ "$(curl_as $FRIEND http://198.18.1.5:8080/)" = BLOCKED ] || fail "(h) friend reached a configured network"
[ "$(curl_as $LAPTOP http://10.99.0.5/)" = vlan ] || fail "(h) personal (all_networks) -> a private subnet through the router"
[ "$(curl_as $GUEST http://9.9.9.9/)" = BLOCKED ] || fail "(h) guest without internet reached a public address"
pass "(h) internet reaches public addresses only; all_networks keeps private space"

# (i) nothing else on the gateway: other ports, the proxy, the Docker bridge, the public address
[ "$(inns gw curl -s -m 3 http://172.17.0.2/)" = container ] || fail "(i) the container is not up"
for src in $GUEST $FRIEND; do
    [ "$(curl_as $src http://172.17.0.1:9090/)" = BLOCKED ] || fail "(i) $src reached the Docker bridge address"
    [ "$(curl_as $src http://172.17.0.2/)" = BLOCKED ] || fail "(i) $src reached a container"
    [ "$(curl_as $src http://203.0.113.1:9090/)" = BLOCKED ] || fail "(i) $src reached the gateway's public address"
    [ "$(curl_as $src http://10.8.0.1:9091/)" = BLOCKED ] || fail "(i) $src reached another port on the gateway"
done
for src in $LAPTOP $FRIEND; do
    [ "$(curl_as $src -k --resolve immich.mydomain.com:8443:10.8.0.1 https://immich.mydomain.com:8443/)" = BLOCKED ] \
        || fail "(i) $src reached the proxy port without a proxied grant"
done
pass "(i) other gateway ports, the proxy port, the Docker bridge and the public address are dropped"

# (j) IPv6: the gateway forwards it, a peer sends it, and the firewall drops it.
# WireGuard alone would drop it (AllowedIPs is IPv4), so widen the guest's on the gateway.
inns gw sysctl -qw net.ipv6.conf.all.forwarding=1
inns gw ip -6 addr add fd00:1::1/64 dev eth0 nodad
inns home ip -6 addr add fd00:1::5/64 dev lan0 nodad
inns home ip -6 route add fd00:8::/64 via fd00:1::1
inns gw ip -6 route add fd00:8::/64 dev wg0
inns client ip -6 addr add fd00:8::2/128 dev wgf nodad
inns client ip -6 route add fd00:1::/64 dev wgf
inns client wg set wgf peer "$GW_PUB" allowed-ips 0.0.0.0/0,::/0
GUEST_PUB=$(inns client wg show wgf public-key)
widen() { inns gw wg set wg0 peer "$GUEST_PUB" allowed-ips 10.8.2.1/32,fd00:8::2/128; }
ping6_as() { inns client ping -6 -c 1 -W 2 -I fd00:8::2 "$1" >/dev/null 2>&1 && echo reached || echo BLOCKED; }
widen
inns gw nft flush chain inet parallax input
inns gw nft flush chain inet parallax forward
[ "$(ping6_as fd00:1::5)" = reached ] || fail "(j) IPv6 setup: without Parallax's rules the guest can't reach home"
[ "$(ping6_as fd00:1::1)" = reached ] || fail "(j) IPv6 setup: without Parallax's rules the guest can't reach the gateway"
apply
widen
[ "$(ping6_as fd00:1::5)" = BLOCKED ] || fail "(j) IPv6 from a peer was forwarded"
[ "$(ping6_as fd00:1::1)" = BLOCKED ] || fail "(j) IPv6 from a peer reached the gateway"
apply   # back to IPv4-only AllowedIPs
pass "(j) IPv6 from a peer is dropped, forwarded or to the gateway"

# (k) revoking a grant cuts connections that are already open: forwarded to the LAN,
# to a service on the gateway host, and through the proxy. The laptop's connection
# is the control: its grants don't change, so it must survive the same apply.
inns client python3 - "$WORK/hold" "$CA" <<'PY' > "$WORK/hold.out" 2>&1 &
import os, socket, ssl, sys, threading, time
gate, ca = sys.argv[1], sys.argv[2]
def tcp(src, addr):
    s = socket.create_connection((addr, 7000), timeout=3, source_address=(src, 0))
    def ask(word):
        s.sendall(word + b"\n")
        return s.recv(64) == word + b"\n"
    return ask
def https(src, addr):
    ctx = ssl.create_default_context(cafile=ca)
    raw = socket.create_connection((addr, 443), timeout=3, source_address=(src, 0))
    s = ctx.wrap_socket(raw, server_hostname="immich.mydomain.com")
    def ask(_):
        s.sendall(b"GET / HTTP/1.1\r\nHost: immich.mydomain.com\r\n\r\n")
        return b"home-immich" in s.recv(4096)
    return ask
cases = [
    ("guest-lan", tcp, "10.8.2.1", "198.18.1.5"),
    ("guest-gateway", tcp, "10.8.2.1", "198.18.1.1"),
    ("guest-proxy", https, "10.8.2.1", "198.18.1.5"),
    ("laptop-lan", tcp, "10.8.1.1", "198.18.1.5"),
]
results = {}
def run(name, kind, src, addr):
    try:
        ask = kind(src, addr)
        if not ask(b"one"):
            results[name] = "BROKEN"; return
        opened.add(name)
        print(f"open {name}", flush=True)
        while not os.path.exists(gate):
            time.sleep(0.1)
        results[name] = "ALIVE" if ask(b"two") else "CLOSED"
    except OSError:
        results[name] = "CLOSED" if name in opened else "BROKEN"
opened = set()
threads = []
for c in cases:
    t = threading.Thread(target=run, args=c); t.start(); threads.append(t)
for t in threads:
    t.join()
for name, *_ in cases:
    print(f"{name} {results.get(name, 'BROKEN')}", flush=True)
PY
PIDS+=($!)
for _ in $(seq 50); do [ "$(grep -c '^open' "$WORK/hold.out")" = 4 ] && break; sleep 0.1; done
[ "$(grep -c '^open' "$WORK/hold.out")" = 4 ] || { cat "$WORK/hold.out"; fail "(k) could not open the held connections"; }
sed "s|^grants = \[$FAMILY_GRANTS\]|grants = [{ kind = \"service\", name = \"gwapp\" }]|" \
    "$WORK/parallax.toml" > "$WORK/revoked.toml"
grep -q '^grants = \[{ kind = "service", name = "gwapp" }\]' "$WORK/revoked.toml" || fail "(k) could not write the revoked config"
apply "$WORK/revoked.toml"
touch "$WORK/hold"
for _ in $(seq 100); do [ "$(grep -cE ' (ALIVE|CLOSED|BROKEN)$' "$WORK/hold.out")" = 4 ] && break; sleep 0.1; done
for c in guest-lan guest-gateway guest-proxy; do
    grep -q "^$c CLOSED$" "$WORK/hold.out" || { cat "$WORK/hold.out"; fail "(k) $c survived the revoked grant"; }
done
grep -q "^laptop-lan ALIVE$" "$WORK/hold.out" || { cat "$WORK/hold.out"; fail "(k) the laptop's connection did not survive an unrelated change"; }
[ "$(https_as $GUEST immich.mydomain.com 198.18.1.5)" = BLOCKED ] || fail "(k) guest opened a new connection after the revoke"
# The DNS server took the same SIGHUP: the name went with the grant.
ST=$(inns client dig +time=2 +tries=1 -b $GUEST @10.8.0.1 immich.mydomain.com | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
[ "$ST" = REFUSED ] || fail "(k) guest still looked up immich after the revoke: '$ST'"
apply   # restore the grants
[ "$(https_as $GUEST immich.mydomain.com 198.18.1.5)" = home-immich ] || fail "(k) guest grant not restored"
ANS=$(inns client dig +short +time=2 +tries=1 -b $GUEST @10.8.0.1 immich.mydomain.com || true)
[ "$ANS" = 198.18.1.5 ] || fail "(k) guest name not restored: '$ANS'"
pass "(k) a revoked grant cuts open connections (LAN, gateway host, proxy) and the name; others survive"

# (l) DNS answers each tier only the names it may reach
status_as() { # src, name, [dig args...]  -> the response status, e.g. NOERROR
    local src=$1 name=$2; shift 2
    inns client dig +time=2 +tries=1 -b "$src" @10.8.0.1 "$name" "$@" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'
}
short_as() { # src, name, [dig args...]
    local src=$1 name=$2; shift 2
    inns client dig +short +time=2 +tries=1 -b "$src" @10.8.0.1 "$name" "$@" || true
}
[ "$(short_as $LAPTOP example.org)" = 9.9.9.9 ] || fail "(l) personal (dns.public) could not look up a public name"
[ -z "$(short_as $LAPTOP rebind.example.org)" ] || fail "(l) a public name answered with a private address"
[ "$(status_as $LAPTOP rebind.example.org)" = NOERROR ] || fail "(l) rebind.example.org: wanted an empty NOERROR"
[ "$(status_as $LAPTOP immich.mydomain.com AAAA)" = NOERROR ] && [ -z "$(short_as $LAPTOP immich.mydomain.com AAAA)" ] \
    || fail "(l) a home name answered AAAA"
[ "$(short_as $LAPTOP vlan.mydomain.com)" = 198.18.1.6 ] \
    || fail "(l) vlan.mydomain.com: wanted only 198.18.1.6, not the address on no configured network"
[ "$(status_as $GUEST other.mydomain.com)" = REFUSED ] || fail "(l) guest looked up a sibling vhost's name"
[ "$(status_as $GUEST example.org)" = REFUSED ] || fail "(l) guest (dns.public off) looked up a public name"
[ "$(status_as $GUEST example.org +tcp)" = REFUSED ] || fail "(l) guest looked up a public name over TCP"
[ "$(status_as $FRIEND example.org)" = REFUSED ] || fail "(l) friend (internet, dns.public off) looked up a public name"
[ "$(status_as $FRIEND immich.mydomain.com)" = REFUSED ] || fail "(l) friend looked up a home name"
ST=$(inns gw dig +time=2 +tries=1 @10.8.0.1 immich.mydomain.com | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
[ "$ST" = REFUSED ] || fail "(l) a source outside every tier got '$ST'"
pass "(l) DNS: personal gets home and public names; guest only its hostname; friend nothing; rebinding answers and unknown private addresses dropped"

# (m) large answers: truncated over plain UDP, then complete over TCP (dig retries itself)
BIG_ANS=$(short_as $LAPTOP big.mydomain.com +noedns)
[ "$(grep -c '^198\.18\.1\.' <<<"$BIG_ANS")" = 40 ] || fail "(m) big.mydomain.com over UDP then TCP: '$BIG_ANS'"
inns client dig +noedns +ignore +time=2 +tries=1 -b $LAPTOP @10.8.0.1 big.mydomain.com | grep -q 'flags: qr tc' \
    || fail "(m) the 512-byte UDP answer was not truncated"
[ "$(short_as $LAPTOP big.mydomain.com +tcp | grep -c '^198\.18\.1\.')" = 40 ] || fail "(m) big.mydomain.com over TCP"
pass "(m) a 40-address answer truncates over UDP and arrives whole over TCP, rewritten"

echo "ALL PASS"
