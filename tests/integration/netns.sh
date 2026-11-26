#!/usr/bin/env bash
# Parallax integration test on Linux network namespaces. Needs root, and:
# nft, wg, ip, dnsmasq, dig, curl, openssl, ping, python3, and the parallax
# binary (PARALLAX=...). KEEP_LOG=<file> keeps a copy of the daemon's log.
# NETNS_PREFIX=<prefix> names the namespaces (default: one per run, so several
# runs can share a machine). Interfaces live inside them and keep their names.
# NETNS_DAEMON=unit runs the daemon (and a doctor) as an unprivileged user under
# packaging/systemd/parallax.service's sandbox and capabilities, as a native
# install does; needs systemd. The default, root, is how the Docker image runs it.
#
# Topology (every namespace is fresh; names below are without the prefix):
#   home    192.168.1.5   "nginx" (TLS, picks the site by Host: immich and a sibling
#           other.mydomain.com) + home DNS + plain HTTP on 8080 + an echo on 7000
#   gw      eth0 192.168.1.1 (home LAN), wan0 203.0.113.1 (clients), up0 (internet),
#           docker0 172.17.0.1 (a Docker bridge); runs `parallax daemon` (apply, DNS,
#           the HTTPS proxy), which the CLI drives over its socket
#   client  wan0 203.0.113.2 -> gw; lan0 192.168.1.10 on a *foreign* LAN with the
#           same prefix as home; WireGuard interfaces wgp (personal), wgf (family)
#           and wgx (friend)
#   foreign 192.168.1.5   the foreign host (same address as home's) + foreign DNS
#   net     the internet: 9.9.9.9 (a public server and the public resolver),
#           1.2.3.4 (stands in for the home's public IP, which the router would
#           hairpin back into the home) and
#           10.99.0.5 (a private subnet the router knows but Parallax doesn't, like
#           another VLAN)
#   ctr     172.17.0.2, a "container" behind the gateway's Docker bridge
#
# Grants: personal (all_networks + internet, public DNS), family (the proxied
# Immich, a service on the gateway host, two echo ports), friend (internet only),
# one peer each; (r) combines them and adds a grant for everyone.
#
# Assertions: (a) mapped virtual IP lands on the real host, (b) the DNS server
# answers in virtual space, (c) guest reaches only its grants even with 0.0.0.0/0
# AllowedIPs, (d) reapply is idempotent, (e) concurrent changes through the daemon,
# (f) colliding guest network with split DNS, (g) the proxy: by name only, one
# hostname, Host/SNI/:authority checked, (h) internet means public addresses,
# (i) nothing else on the gateway, its Docker bridge or the public address,
# (j) IPv6 from a peer is dropped, (k) a revoked grant cuts open connections,
# (l) DNS answers each tier only its names, and no private address outside the
# configured networks, (m) large DNS answers, (o) guests with internet can't reach
# the home's public IP, and a lookup answered with a private address is refused,
# (p) hosts granted by DNS name are looked up on save and bad ones refused, (q) names
# on the home's public IP reach one port forward each, or HTTPS through the proxy,
# (n) the daemon tears down on SIGTERM, re-applies on SIGHUP and repairs a deleted
# table, and keeps the home's public IP across the restart, (r) a peer with two grants
# reaches both and nothing more, a grant for everyone reaches every peer, and changing
# grants keeps addresses and client configs, (s) `grant` and `peer grants` commands
# change access when they return, and a refused one changes nothing. Every change
# goes through the daemon and takes effect without SIGHUP.
set -euo pipefail

PARALLAX="${PARALLAX:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/parallax}"
[ -x "$PARALLAX" ] || { echo "parallax binary not found at $PARALLAX (cargo build first)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for t in nft wg ip dnsmasq dig curl openssl ping python3; do command -v $t >/dev/null || { echo "missing $t"; exit 2; }; done

PREFIX="${NETNS_PREFIX-pxit$$-}"
[[ $PREFIX =~ ^[A-Za-z0-9_-]*$ ]] || { echo "NETNS_PREFIX may hold only letters, digits, _ and -"; exit 2; }
NAMESPACES=""
for ns in home gw client foreign net ctr; do NAMESPACES+=" $PREFIX$ns"; done
# Cleanup kills everything in these namespaces, so never adopt ones that already exist.
for ns in $NAMESPACES; do
    ip netns list | grep -q "^$ns\( \|$\)" && { echo "namespace $ns already exists; delete it first"; exit 2; }
done

MODE="${NETNS_DAEMON:-root}"
case $MODE in
    root) ;;
    unit) command -v systemd-run >/dev/null && [ -d /run/systemd/system ] \
              || { echo "NETNS_DAEMON=unit needs systemd"; exit 2; } ;;
    *) echo "NETNS_DAEMON is root or unit"; exit 2 ;;
esac
UNIT_FILE="$(cd "$(dirname "$0")/../.." && pwd)/packaging/systemd/parallax.service"

# The unit's private /tmp would hide one under /tmp.
WORK=$(mktemp -d "$([ "$MODE" = unit ] && echo /run || echo /tmp)/parallax-it.XXXXXX")
PIDS=()
UNITS=()
CREATED=() # only these are cleaned up: a run that lost a race for a name leaves the winner's alone
cleanup() {
    set +e
    for u in "${UNITS[@]:-}"; do [ -n "$u" ] && systemctl stop "$u" 2>/dev/null; done
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    # $! above is the backgrounded `inns` subshell, not the server it starts: kill
    # whatever still runs in each namespace, or they outlive the test and keep the
    # caller's stdout open.
    for ns in "${CREATED[@]:-}"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
    done
    sleep 0.2
    for ns in "${CREATED[@]:-}"; do ip netns del "$ns" 2>/dev/null; done
    [ -n "${KEEP_LOG:-}" ] && cp "$WORK/daemon.log" "$KEEP_LOG"
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*"
    [ -s "$WORK/daemon.log" ] && { echo "--- daemon log"; tail -30 "$WORK/daemon.log"; }
    exit 1
}
inns() { local ns=$PREFIX$1; shift; ip netns exec "$ns" "$@"; } # role (gw, home, ...), command

# ---------------------------------------------------------------- topology
for ns in $NAMESPACES; do ip netns add "$ns"; CREATED+=("$ns"); ip netns exec "$ns" ip link set lo up; done
veth() { ip link add "$1" netns "$PREFIX$2" type veth peer name "$3" netns "$PREFIX$4"; } # name, ns, peer, ns
veth eth0 gw lan0 home
veth wan0 gw wan0 client
veth lan0 client lan0 foreign
veth up0 gw up0 net
veth vethctr gw eth0 ctr
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
inns net ip addr add 1.2.3.4/32 dev lo
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
    printf 'subjectAltName=DNS:immich.mydomain.com,DNS:other.mydomain.com,DNS:public.mydomain.com\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' > leaf.ext
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
    # Quiet: held connections end in resets when (n) tears the gateway down.
    inns "$1" python3 - "$2" 2>/dev/null <<'PY' &
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
serve net 1.2.3.4 80 home-public
serve net 1.2.3.4 8080 home-public-other
# A web server behind the home's public IP (a port forward), with every site on it.
inns net python3 - "$WORK/ca/leaf.pem" "$WORK/ca/leaf.key" <<'PY' &
import sys, ssl, http.server
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = ("forwarded-" + (self.headers.get("Host") or "").split(":")[0]).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("1.2.3.4", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
PIDS+=($!)
serve ctr 0.0.0.0 80 container
# Home DNS: authoritative-ish answers for mydomain.com (big.mydomain.com has 40
# addresses, more than a 512-byte UDP answer holds); foreign DNS for hisdomain.com;
# a "public resolver" on the internet, with one name that points into private space.
BIG=()
for i in $(seq 10 49); do BIG+=(--host-record=big.mydomain.com,192.168.1.$i); done
inns home dnsmasq --conf-file=/dev/null --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
    --address=/immich.mydomain.com/192.168.1.5 --address=/other.mydomain.com/192.168.1.5 \
    --host-record=vlan.mydomain.com,10.99.0.5 --host-record=vlan.mydomain.com,192.168.1.6 \
    --host-record=web.mydomain.com,192.168.1.5 --host-record=away.mydomain.com,10.99.0.5 \
    --host-record=game.mydomain.com,1.2.3.4 --host-record=public.mydomain.com,1.2.3.4 \
    "${BIG[@]}" >/dev/null 2>&1 &
PIDS+=($!)
inns net dnsmasq --conf-file=/dev/null --no-daemon --no-resolv --no-hosts --listen-address=9.9.9.9 --bind-interfaces \
    --address=/example.org/9.9.9.9 --address=/rebind.example.org/192.168.1.5 >/dev/null 2>&1 &
PIDS+=($!)
inns foreign dnsmasq --conf-file=/dev/null --no-daemon --no-resolv --no-hosts --listen-address=192.168.1.5 --bind-interfaces \
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
[server.backup]
directory = "$WORK/backups"
passphrase_file = "$WORK/backup.passphrase"
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
[[grant]]
name = "personal"
rules = [{ kind = "all_networks" }, { kind = "internet" }, { kind = "public_dns" }]
[[grant]]
name = "family"
rules = [$FAMILY_GRANTS]
[[grant]]
name = "friend"
rules = [{ kind = "internet" }]
TOML
SOCK="$WORK/run/parallax.sock"
P="$PARALLAX --db $WORK/parallax.db --socket $SOCK"
$P config import "$WORK/parallax.toml" >/dev/null
$P keygen --write-config >/dev/null
# Addresses come from the supernet in order: 10.8.0.2, .3, .4.
$P peer add laptop --grant personal --keep-private-key --platform linux > "$WORK/laptop.conf" 2>/dev/null
$P peer add guest --grant family --dns tunnel_wide --allowed-ips grants_only --keep-private-key \
    --platform mobile > "$WORK/guest.conf" 2>/dev/null
$P peer add friend --grant friend --allowed-ips full_tunnel --keep-private-key --platform linux \
    > "$WORK/friend.conf" 2>/dev/null
$P validate >/dev/null
inns gw $P doctor > "$WORK/doctor" || { cat "$WORK/doctor"; fail "doctor rejects the gateway namespace"; }
# Root in a user namespace (as under rootless Docker) must be refused. That root
# maps only uid 0, so run a copy it can reach (not one under someone's home).
cp "$PARALLAX" "$WORK/parallax"
if inns gw unshare -U -r "$WORK/parallax" --db "$WORK/parallax.db" --socket "$SOCK" doctor > "$WORK/doctor-userns" 2>&1; then
    fail "doctor accepted a user namespace"
fi
grep -q "^FAIL  user namespace" "$WORK/doctor-userns" || fail "doctor did not name the user namespace"
pass "doctor passes on the gateway and refuses a user namespace"

# As a native install runs it: `nobody` (the test's stand-in for the `parallax`
# user) in the gateway namespace, with the unit's sandbox and capabilities. Only
# what names the unit's own install (its user, paths, commands) is left out; the
# test brings its own.
if [ "$MODE" = unit ]; then
    SANDBOX=()
    while IFS= read -r line; do
        case ${line%%=*} in
            Type | User | Group | Exec* | Restart* | StateDirectory* | RuntimeDirectory* | ReadWritePaths) ;;
            *) SANDBOX+=(-p "$line") ;;
        esac
    done < <(sed -n '/^\[Service\]/,/^\[/p' "$UNIT_FILE" | grep -E '^[A-Za-z]+=')
    printf '%s\n' "${SANDBOX[@]}" | grep -q '^AmbientCapabilities=CAP_NET_ADMIN' \
        || fail "could not read the sandbox from $UNIT_FILE"
    AS_UNIT=(systemd-run --quiet --collect -p User=nobody -p "NetworkNamespacePath=/run/netns/${PREFIX}gw"
        -p "ReadWritePaths=$WORK" "${SANDBOX[@]}")
    # A first start from nothing: the unit's own ExecStartPre lines, in order,
    # pointed at a fresh directory.
    for d in first bad none; do mkdir "$WORK/$d"; done
    sed "s|^private_key_file = .*|private_key_file = \"$WORK/first/wg-server.key\"|" "$WORK/parallax.toml" \
        > "$WORK/first/parallax.toml"
    printf '[server\n' > "$WORK/bad/parallax.toml"
    chown -R nobody "$WORK"
    starts=0
    first_start() { # directory
        local line
        while IFS= read -r line; do
            line=${line#ExecStartPre=}
            line=${line//\/usr\/bin\/parallax/"$WORK/parallax --db $1/parallax.db --socket $1/parallax.sock"}
            line=${line//\/etc\/parallax\/parallax.toml/"$1/parallax.toml"}
            starts=$((starts + 1))
            "${AS_UNIT[@]}" --unit="${PREFIX}first-$starts" --wait --pipe /bin/sh -c "$line" || return 1
        done < <(grep '^ExecStartPre=' "$UNIT_FILE")
    }
    first_start "$WORK/first" > "$WORK/first.out" 2>&1 \
        || { cat "$WORK/first.out"; fail "the unit's first start (import, doctor, keygen) fails as the service"; }
    grep -q "^imported" "$WORK/first.out" || { cat "$WORK/first.out"; fail "the first start did not import the TOML"; }
    [ "$(stat -c '%U %a' "$WORK/first/wg-server.key")" = "nobody 600" ] \
        || fail "the first start's server key is not the service's own, 0600"
    if first_start "$WORK/bad" > "$WORK/bad.out" 2>&1; then fail "a broken TOML did not stop the first start"; fi
    grep -q "^imported" "$WORK/bad.out" && fail "a broken TOML was imported"
    if first_start "$WORK/none" > "$WORK/none.out" 2>&1; then fail "a start with no TOML and no database passed"; fi
    grep -q "^FAIL  configuration" "$WORK/none.out" \
        || { cat "$WORK/none.out"; fail "with no TOML, doctor did not say there's no configuration"; }
    pass "the unit's first start: imports, checks and makes the key as the service; a broken TOML stops it"
    "${AS_UNIT[@]}" --unit="${PREFIX}doctor" --wait --pipe \
        "$WORK/parallax" --db "$WORK/parallax.db" --socket "$SOCK" doctor > "$WORK/doctor-unit" 2>&1 \
        || { cat "$WORK/doctor-unit"; fail "doctor fails as the native service"; }
    grep -q "^ok    CAP_NET_ADMIN: held, and ambient" "$WORK/doctor-unit" \
        || { cat "$WORK/doctor-unit"; fail "doctor did not see CAP_NET_ADMIN as ambient"; }
    pass "doctor passes as the native service: unprivileged, sandboxed, two ambient capabilities"
fi

# The daemon applies, then serves DNS and the proxy on the tunnel address. Drift
# checks are hourly here, so the tests below can change live rules on purpose;
# (n) restarts it with a short interval.
start_daemon() { # reconcile interval in seconds
    local unit="${PREFIX}daemon-${#UNITS[@]}"
    if [ "$MODE" = unit ]; then
        UNITS+=("$unit")
        "${AS_UNIT[@]}" --unit="$unit" -p "StandardOutput=append:$WORK/daemon.log" \
            -p "StandardError=append:$WORK/daemon.log" \
            "$WORK/parallax" --db "$WORK/parallax.db" --socket "$SOCK" \
            daemon -o "$WORK/out" --reconcile-every "$1"
    else
        inns gw sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/daemon.pid" \
            $P daemon -o "$WORK/out" --reconcile-every "$1" >> "$WORK/daemon.log" 2>&1 &
        PIDS+=($!)
    fi
    for _ in $(seq 100); do
        if $P status >/dev/null 2>&1 && inns gw ss -Hltn 'sport = :53' | grep -q . \
            && inns gw ss -Hltn 'sport = :8443' | grep -q .; then
            if [ "$MODE" = unit ]; then
                # 0 would mean it already exited, and `kill 0` hits this whole test.
                local pid
                pid=$(systemctl show -p MainPID --value "$unit")
                [ "${pid:-0}" -gt 0 ] || fail "the daemon's unit $unit has no main process"
                echo "$pid" > "$WORK/daemon.pid"
            fi
            return 0
        fi
        sleep 0.1
    done
    fail "parallax daemon did not start"
}
start_daemon 3600
[ "$(stat -c %a "$SOCK")" = 600 ] && [ "$(stat -c %a "$WORK/run")" = 700 ] \
    || fail "the socket or its directory is not owner-only"
# The server's key comes first in the export, before any peer's.
GW_PUB=$($P config export | sed -n 's/^public_key = "\(.*\)"/\1/p' | head -n1)

# Through the daemon: an import applies on save, `apply` re-applies. No SIGHUP;
# the DNS server and the proxy re-read their routes right after the apply.
apply() { # [TOML file to import]
    if [ -n "${1:-}" ]; then
        $P config import "$1" >/dev/null 2>&1 || fail "import of $1 through the daemon failed"
    else
        $P apply >/dev/null || fail "apply through the daemon failed"
    fi
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
mkclient wgp "$WORK/laptop.conf" 10.8.0.2
mkclient wgf "$WORK/guest.conf" 10.8.0.3
mkclient wgx "$WORK/friend.conf" 10.8.0.4
# Split tunnel routes for the laptop: virtual range, the gateway and the test's internet hosts.
for dst in 198.18.1.0/24 10.8.0.1/32 9.9.9.9/32 10.99.0.5/32 1.2.3.4/32; do
    inns client ip route add $dst dev wgp src 10.8.0.2
done
# Guest and friend send everything through their tunnel (full tunnel), in their own
# routing tables so all three tunnels coexist in one namespace.
inns client ip rule add from 10.8.0.3 table 200
inns client ip route add default dev wgf table 200
inns client ip rule add from 10.8.0.4 table 201
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

LAPTOP=10.8.0.2 GUEST=10.8.0.3 FRIEND=10.8.0.4

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

# (e) changes through the daemon: eight `peer add`s at once all land, with distinct
# addresses, and are live on wg0 when each command returns (one writer, no SIGHUP)
ADDS=()
for i in $(seq 8); do
    $P peer add "dev$i" --grant family >/dev/null 2>"$WORK/add$i.err" &
    ADDS+=($!)
done
for i in $(seq 8); do
    wait "${ADDS[$((i - 1))]}" || { cat "$WORK/add$i.err"; fail "(e) concurrent peer add dev$i failed"; }
done
ADDRS=$($P peer show | sed -n 's/^dev[0-9]* .*address=\([^ ]*\).*/\1/p' | sort -u)
[ "$(grep -c . <<<"$ADDRS")" = 8 ] || fail "(e) eight peers, eight addresses: '$ADDRS'"
[ "$(inns gw wg show wg0 peers | grep -c .)" = 11 ] || fail "(e) the new peers are not on wg0"
for i in $(seq 8); do $P peer remove "dev$i" >/dev/null 2>&1 || fail "(e) peer remove dev$i"; done
[ "$(inns gw wg show wg0 peers | grep -c .)" = 3 ] || fail "(e) removed peers are still on wg0"
grep -q 'applying (SIGHUP)' "$WORK/daemon.log" && fail "(e) something sent SIGHUP"
pass "(e) concurrent peer adds through the daemon land with distinct addresses and apply on save"

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

# (h) internet: public addresses only, except for an all_networks tier
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
widen() { inns gw wg set wg0 peer "$GUEST_PUB" allowed-ips 10.8.0.3/32,fd00:8::2/128; }
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
    ("guest-lan", tcp, "10.8.0.3", "198.18.1.5"),
    ("guest-gateway", tcp, "10.8.0.3", "198.18.1.1"),
    ("guest-proxy", https, "10.8.0.3", "198.18.1.5"),
    ("laptop-lan", tcp, "10.8.0.2", "198.18.1.5"),
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
# The whole configuration (peers included), and a copy whose family grant
# keeps only its gwapp rule.
$P config export > "$WORK/full.toml"
python3 - "$WORK/full.toml" > "$WORK/revoked.toml" <<'PY'
# `config export` writes several rules one per line inside `rules = [`.
import sys
grant, in_rules = None, False
for line in open(sys.argv[1]):
    if line.startswith("[["):
        grant = None
    elif line.startswith("name = ") and grant is None:
        grant = line.split('"')[1]
    if line.startswith("rules = ["):
        in_rules = line.rstrip().endswith("[")
    elif in_rules and line.startswith("]"):
        in_rules = False
    elif in_rules and grant == "family" and '"gwapp"' not in line:
        continue
    sys.stdout.write(line)
PY
python3 - "$WORK/full.toml" "$WORK/revoked.toml" <<'PY' || fail "(k) could not write the revoked config"
import sys, tomllib
def rules(path):
    g = next(g for g in tomllib.load(open(path, "rb"))["grant"] if g["name"] == "family")
    return g["rules"]
full, revoked = rules(sys.argv[1]), rules(sys.argv[2])
assert len(full) == 4 and revoked == [{"kind": "service", "name": "gwapp"}], (full, revoked)
PY
apply "$WORK/revoked.toml"
touch "$WORK/hold"
for _ in $(seq 100); do [ "$(grep -cE ' (ALIVE|CLOSED|BROKEN)$' "$WORK/hold.out")" = 4 ] && break; sleep 0.1; done
for c in guest-lan guest-gateway guest-proxy; do
    grep -q "^$c CLOSED$" "$WORK/hold.out" || { cat "$WORK/hold.out"; fail "(k) $c survived the revoked grant"; }
done
grep -q "^laptop-lan ALIVE$" "$WORK/hold.out" || { cat "$WORK/hold.out"; fail "(k) the laptop's connection did not survive an unrelated change"; }
[ "$(https_as $GUEST immich.mydomain.com 198.18.1.5)" = BLOCKED ] || fail "(k) guest opened a new connection after the revoke"
# The DNS server re-read its routes after the same apply: the name went with the grant.
ST=$(inns client dig +time=2 +tries=1 -b $GUEST @10.8.0.1 immich.mydomain.com | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
[ "$ST" = REFUSED ] || fail "(k) guest still looked up immich after the revoke: '$ST'"
apply "$WORK/full.toml"   # restore the grants
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
[ "$(short_as $LAPTOP example.org)" = 9.9.9.9 ] || fail "(l) personal (public_dns) could not look up a public name"
[ -z "$(short_as $LAPTOP rebind.example.org)" ] || fail "(l) a public name answered with a private address"
[ "$(status_as $LAPTOP rebind.example.org)" = NOERROR ] || fail "(l) rebind.example.org: wanted an empty NOERROR"
[ "$(status_as $LAPTOP immich.mydomain.com AAAA)" = NOERROR ] && [ -z "$(short_as $LAPTOP immich.mydomain.com AAAA)" ] \
    || fail "(l) a home name answered AAAA"
[ "$(short_as $LAPTOP vlan.mydomain.com)" = 198.18.1.6 ] \
    || fail "(l) vlan.mydomain.com: wanted only 198.18.1.6, not the address on no configured network"
[ "$(status_as $GUEST other.mydomain.com)" = REFUSED ] || fail "(l) guest looked up a sibling vhost's name"
[ "$(status_as $GUEST example.org)" = REFUSED ] || fail "(l) guest (no public_dns) looked up a public name"
[ "$(status_as $GUEST example.org +tcp)" = REFUSED ] || fail "(l) guest looked up a public name over TCP"
[ "$(status_as $FRIEND example.org)" = REFUSED ] || fail "(l) friend (internet, no public_dns) looked up a public name"
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

# (p) a host granted by name: looked up through its network's resolver when the change
# is saved; the tier reaches that port and may look the name up. A name that doesn't
# resolve is refused, and so is one that resolves outside every configured network.
$P config export > "$WORK/named-before.toml"
grep -q 'host = "192.168.1.5", ports = \["7000/tcp"\]' "$WORK/named-before.toml" \
    || fail "(p) host_port grants written with ip = ... don't export as host grants with ports"
named() { # host -> a config granting family a few ports on it, 8080/tcp among them
    sed "/host = \"192.168.1.5\", ports = \[\"7000\/tcp\"\] }/a\\
    { kind = \"host\", host = \"$1\", ports = [\"8080\/tcp\", \"5353\/udp\", \"9000-9010\/tcp\"] }," \
        "$WORK/named-before.toml" > "$WORK/named-$1.toml"
    echo "$WORK/named-$1.toml"
}
[ "$(status_as $GUEST web.mydomain.com)" = REFUSED ] || fail "(p) guest looked up a name it isn't granted"
apply "$(named web.mydomain.com)"
grep -qx "name web.mydomain.com: 192.168.1.5" <<<"$($P status)" || { $P status; fail "(p) the name was not looked up on save"; }
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = home-other ] || fail "(p) guest -> the host granted by name"
[ "$(short_as $GUEST web.mydomain.com)" = 198.18.1.5 ] || fail "(p) guest could not look up the name it's granted"
refused() { # host, what the refusal must say
    if $P config import "$(named "$1")" > "$WORK/named.err" 2>&1; then
        fail "(p) a save granting $1 was accepted"
    fi
    grep -qF "$2" "$WORK/named.err" || { cat "$WORK/named.err"; fail "(p) the refusal of $1 doesn't say why"; }
}
refused nosuch.mydomain.com "nosuch.mydomain.com"
refused away.mydomain.com "away.mydomain.com resolved to 10.99.0.5, outside every configured network"
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = home-other ] || fail "(p) a refused save changed the gateway"
apply "$WORK/named-before.toml"
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = BLOCKED ] || fail "(p) the grant by name outlived its removal"
grep -q "^name " <<<"$($P status)" && fail "(p) a name no longer used is still listed"
pass "(p) a host granted by name: looked up on save, reached on its port, its name answers; bad names are refused"

# (o) the home's public IP: guests with internet drop it (the router would hairpin it
# back into the home); the owner's all_networks tier doesn't. The endpoint here
# is a documentation address, so not the public IP; a fixed address counts the moment
# it's saved. A hostname is looked up and re-applied when it changes; an answer with
# a private address is refused, and the last address found stays.
public_ip_is() { # address
    for _ in $(seq 50); do grep -qx "home public IP: $1" <<<"$($P status)" && return 0; sleep 0.1; done
    $P status; return 1
}
grep -q "home public IP" <<<"$($P status)" && fail "(o) the private endpoint was taken as the public IP"
grep -q "the endpoint 203.0.113.1:51820 is not a public address" "$WORK/daemon.log" \
    || fail "(o) the daemon did not say why the public IP is unknown"
$P config export > "$WORK/public-ip.toml"
sed -i 's/^\[server.public_ip\]$/&\naddress = "1.2.3.4"/' "$WORK/public-ip.toml"
apply "$WORK/public-ip.toml"
public_ip_is 1.2.3.4 || fail "(o) a saved public_ip.address is not in effect"
[ "$(curl_as $FRIEND http://1.2.3.4/)" = BLOCKED ] || fail "(o) friend reached the home's public IP"
[ "$(curl_as $FRIEND http://9.9.9.9/)" = internet ] || fail "(o) friend lost the internet"
[ "$(curl_as $LAPTOP http://1.2.3.4/)" = home-public ] || fail "(o) personal (all_networks) can't reach the home's public IP"
# A hostname the public resolver answers with 9.9.9.9 (dnsmasq answers all of example.org).
sed -e '/^address = "1.2.3.4"$/d' -e 's/^endpoint = .*/endpoint = "home.example.org:51820"/' \
    "$WORK/public-ip.toml" > "$WORK/public-ip-name.toml"
apply "$WORK/public-ip-name.toml"
public_ip_is 9.9.9.9 || fail "(o) the endpoint's hostname was not looked up"
for _ in $(seq 50); do grep -q "applying (the home's public IP changed)" "$WORK/daemon.log" && break; sleep 0.1; done
grep -q "applying (the home's public IP changed)" "$WORK/daemon.log" || fail "(o) no re-apply for the looked-up address"
sleep 0.3
[ "$(curl_as $FRIEND http://9.9.9.9/)" = BLOCKED ] || fail "(o) friend reached the looked-up public IP"
[ "$(curl_as $FRIEND http://1.2.3.4/)" = home-public ] || fail "(o) the old address is still dropped"
sed -e 's/^endpoint = .*/endpoint = "rebind.example.org:51820"/' \
    "$WORK/public-ip-name.toml" > "$WORK/public-ip-rebind.toml"
apply "$WORK/public-ip-rebind.toml"
for _ in $(seq 50); do grep -q "isn't a public address" "$WORK/daemon.log" && break; sleep 0.1; done
grep -q "rebind.example.org through 9.9.9.9: answered 192.168.1.5, which isn't a public address" "$WORK/daemon.log" \
    || fail "(o) a private answer was not refused"
grep -q "keeping the last known 9.9.9.9" "$WORK/daemon.log" || fail "(o) the last known address was not kept"
public_ip_is 9.9.9.9 || fail "(o) the address changed after a refused answer"
[ "$(curl_as $FRIEND http://9.9.9.9/)" = BLOCKED ] || fail "(o) friend reached the home's public IP after a refused lookup"
pass "(o) guests drop the home's public IP: configured, looked up and re-applied on change; a private answer is refused"

# (n) the daemon's lifecycle: SIGTERM takes the gateway down and removes the socket;
# a new daemon re-applies on SIGHUP and puts back a table someone deleted.
DAEMON=$(cat "$WORK/daemon.pid")
kill -TERM "$DAEMON"
for _ in $(seq 50); do kill -0 "$DAEMON" 2>/dev/null || break; sleep 0.1; done
kill -0 "$DAEMON" 2>/dev/null && fail "(n) the daemon did not stop on SIGTERM"
inns gw nft list table inet parallax >/dev/null 2>&1 && fail "(n) the table outlived the daemon"
inns gw ip link show wg0 >/dev/null 2>&1 && fail "(n) wg0 outlived the daemon"
[ -e "$SOCK" ] && fail "(n) the socket outlived the daemon"
if [ "$MODE" = unit ]; then
    # Root opening the service's database would leave files the service can't open.
    if $P validate > "$WORK/root.err" 2>&1; then fail "(n) root opened the service's database directly"; fi
    grep -q "belongs to user 'nobody', and no daemon answers" "$WORK/root.err" \
        || { cat "$WORK/root.err"; fail "(n) root's refusal doesn't say whose database it is"; }
    if inns gw timeout 20 $P daemon -o "$WORK/out" > "$WORK/root-daemon.err" 2>&1; then
        fail "(n) root ran a daemon on the service's database"
    fi
    grep -q "a daemon run as root would leave files that user can't open" "$WORK/root-daemon.err" \
        || { cat "$WORK/root-daemon.err"; fail "(n) root's daemon didn't say why it refused"; }
    inns gw nft list table inet parallax >/dev/null 2>&1 && fail "(n) root's refused daemon applied anyway"
    runuser -u nobody -- "$WORK/parallax" --db "$WORK/parallax.db" --socket "$SOCK" validate >/dev/null \
        || fail "(n) without a daemon the service's user opens the database itself"
else
    $P validate >/dev/null || fail "(n) without a daemon the CLI opens the database itself"
fi
start_daemon 1
# wg0 is new: the clients' sessions are gone until they handshake again (up to ~15 s).
for _ in $(seq 10); do [ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] && break; done
[ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] || fail "(n) traffic after a restart"
# The lookup still fails (see (o)); the address from before the restart stays.
public_ip_is 9.9.9.9 || fail "(n) the home's public IP was lost in the restart"
[ "$(curl_as $FRIEND http://9.9.9.9/)" = BLOCKED ] || fail "(n) friend reached the home's public IP after a restart"
before=$(grep -c 'applying (SIGHUP)' "$WORK/daemon.log" || true)
kill -HUP "$(cat "$WORK/daemon.pid")"
for _ in $(seq 50); do [ "$(grep -c 'applying (SIGHUP)' "$WORK/daemon.log")" -gt "$before" ] && break; sleep 0.1; done
[ "$(grep -c 'applying (SIGHUP)' "$WORK/daemon.log")" -gt "$before" ] || fail "(n) SIGHUP did not re-apply"
sleep 3   # a few idle reconcile ticks: an unchanged gateway must not count as drift
grep -q 'applying (the live' "$WORK/daemon.log" && fail "(n) an unchanged gateway was taken for drift"
inns gw nft delete table inet parallax
for _ in $(seq 50); do inns gw nft list table inet parallax >/dev/null 2>&1 && break; sleep 0.1; done
inns gw nft list table inet parallax >/dev/null 2>&1 || fail "(n) the deleted table did not come back"
grep -q 'applying (the live' "$WORK/daemon.log" || fail "(n) the repair was not logged as drift"
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = BLOCKED ] || fail "(n) guest grants after the repair"
[ "$(curl_as $LAPTOP http://198.18.1.5:8080/)" = home-other ] || fail "(n) traffic after the repair"
pass "(n) SIGTERM tears down; SIGHUP re-applies; a deleted table comes back on its own"

# (q) names on the home's public IP are port forwards: friend (full tunnel, internet,
# which drops the public IP) reaches the one port it's granted there, and HTTPS by name
# through the proxy, which connects to the public IP itself. A host grant there (every
# port) and a raw web port are refused.
$P config export > "$WORK/current.toml"
sed -e 's/^\[server.public_ip\]$/&\naddress = "1.2.3.4"/' \
    -e '0,/^\[\[grant\]\]$/s//[[service]]\nname = "forwarded"\nhost = "public.mydomain.com"\nports = ["443\/tcp"]\nhostnames = ["public.mydomain.com"]\n\n&/' \
    "$WORK/current.toml" > "$WORK/forward-base.toml"
grep -q '^address = "1.2.3.4"$' "$WORK/forward-base.toml" && grep -q '^name = "forwarded"$' "$WORK/forward-base.toml" \
    || fail "(q) could not write the test configuration"
forward() { # extra friend grants -> a config file
    sed "s|^rules = \[{ kind = \"internet\" }\]\$|rules = [{ kind = \"internet\" }, $1]|" \
        "$WORK/forward-base.toml" > "$WORK/forward.toml"
    grep -qF "$1" "$WORK/forward.toml" || fail "(q) could not grant friend $1"
    echo "$WORK/forward.toml"
}
apply "$(forward '{ kind = "host", host = "game.mydomain.com", ports = ["8080/tcp"] }, { kind = "service", name = "forwarded" }')"
# Friend's session may still be handshaking with the daemon (n) restarted.
for _ in $(seq 10); do [ "$(curl_as $FRIEND http://9.9.9.9/)" = internet ] && break; done
grep -qx "name game.mydomain.com: 1.2.3.4" <<<"$($P status)" || { $P status; fail "(q) game.mydomain.com was not looked up"; }
[ "$(curl_as $FRIEND http://1.2.3.4:8080/)" = home-public-other ] || fail "(q) friend -> the granted port forward"
[ "$(curl_as $FRIEND http://1.2.3.4/)" = BLOCKED ] || fail "(q) friend reached another port on the public IP"
[ "$(short_as $FRIEND game.mydomain.com)" = 1.2.3.4 ] || fail "(q) friend could not look up the forwarded name"
[ "$(https_as $FRIEND public.mydomain.com 1.2.3.4)" = forwarded-public.mydomain.com ] \
    || fail "(q) friend -> HTTPS by name through the proxy to the public IP"
[ "$(https_as $FRIEND other.mydomain.com 1.2.3.4)" = BLOCKED ] || fail "(q) friend reached another site behind the forward"
[ "$(https_as $FRIEND other.mydomain.com 1.2.3.4 -k)" = BLOCKED ] || fail "(q) friend reached another site (no verify)"
[ "$(curl_as $FRIEND http://9.9.9.9/)" = internet ] || fail "(q) friend lost the internet"
refused_forward() { # grant, what the refusal must say
    if $P config import "$(forward "$1")" > "$WORK/forward.err" 2>&1; then
        fail "(q) a save granting friend $1 was accepted"
    fi
    grep -qF "$2" "$WORK/forward.err" || { cat "$WORK/forward.err"; fail "(q) the refusal of $1 doesn't say why"; }
}
refused_forward '{ kind = "host", host = "game.mydomain.com" }' "every port there is a port forward"
refused_forward '{ kind = "host", host = "game.mydomain.com", ports = ["80/tcp"] }' "grant it as a service with hostnames"
apply "$WORK/forward-base.toml"
[ "$(curl_as $FRIEND http://1.2.3.4:8080/)" = BLOCKED ] || fail "(q) the port forward outlived its grant"
pass "(q) names on the home's public IP: one granted port, HTTPS by name through the proxy; all ports and raw web refused"

# (r) grants combine: friend also gets family and reaches both, nothing more; a grant
# for everyone reaches every peer without being attached; and none of it changes an
# address or what a client config holds (only comments may differ).
FRIEND_CONF=$($P export friend --platform linux 2>/dev/null | grep -v '^#')
sed '/^name = "friend"$/{n;s/^grants = \["friend"\]$/grants = ["friend", "family"]/}' \
    "$WORK/forward-base.toml" > "$WORK/union.toml"
grep -q '^grants = \["friend", "family"\]$' "$WORK/union.toml" || fail "(r) could not give friend two grants"
apply "$WORK/union.toml"
grep -q '^friend  grants=family,friend  .*address=10.8.0.4 ' <<<"$($P peer show friend)" \
    || { $P peer show friend; fail "(r) friend's grants or address"; }
[ "$(https_as $FRIEND immich.mydomain.com 198.18.1.5)" = home-immich ] || fail "(r) friend -> family's Immich"
[ "$(curl_as $FRIEND http://198.18.1.1:9090/)" = gw-self ] || fail "(r) friend -> family's service on the gateway"
[ "$(curl_as $FRIEND http://9.9.9.9/)" = internet ] || fail "(r) friend lost its own internet"
[ "$(curl_as $FRIEND http://198.18.1.5:8080/)" = BLOCKED ] || fail "(r) friend reached what neither grant gives"
[ "$(short_as $FRIEND immich.mydomain.com)" = 198.18.1.5 ] || fail "(r) friend could not look up family's name"
[ "$(curl_as $GUEST http://9.9.9.9/)" = BLOCKED ] || fail "(r) guest got friend's internet"
sed '/^# Peers$/i\
[[grant]]\
name = "everyone-web"\
everyone = true\
rules = [{ kind = "host", host = "192.168.1.5", ports = ["8080/tcp"] }]\
' "$WORK/union.toml" > "$WORK/everyone.toml"
apply "$WORK/everyone.toml"
for src in $LAPTOP $GUEST $FRIEND; do
    [ "$(curl_as $src http://198.18.1.5:8080/)" = home-other ] || fail "(r) $src missed the grant for everyone"
done
[ "$($P export friend --platform linux 2>/dev/null | grep -v '^#')" = "$FRIEND_CONF" ] \
    || fail "(r) friend's client config changed with its grants"
apply "$WORK/forward-base.toml"
[ "$(curl_as $GUEST http://198.18.1.5:8080/)" = BLOCKED ] || fail "(r) the grant for everyone outlived its removal"
[ "$(https_as $FRIEND immich.mydomain.com 198.18.1.5)" = BLOCKED ] || fail "(r) friend kept family after it was detached"
pass "(r) two grants reach their union and nothing more; a grant for everyone reaches every peer; addresses and client configs stay"

# (s) the same from the command line: each `grant` and `peer grants` command is live
# when it returns, and one that's refused (a rule that isn't there, a grant someone
# still has) leaves access as it was. Laptop's own grants never change: the control.
GUEST_CONF=$($P export guest --platform mobile 2>/dev/null | grep -v '^#')
g() { $P "$@" >/dev/null 2>"$WORK/grant.err" || { cat "$WORK/grant.err"; fail "(s) parallax $*"; }; sleep 0.3; }
refused() { if $P "$@" >/dev/null 2>&1; then fail "(s) parallax $* should be refused"; fi; }
web() { curl_as "$1" http://198.18.1.5:8080/; }
[ "$(web $GUEST)" = BLOCKED ] || fail "(s) guest reached 8080 before any grant gave it"
g grant create web host:192.168.1.5:8080/tcp
[ "$(web $GUEST)" = BLOCKED ] || fail "(s) a grant attached to no one gave access"
g grant attach web --to guest
[ "$(web $GUEST)" = home-other ] || fail "(s) guest -> its attached grant"
[ "$(web $FRIEND)" = BLOCKED ] || fail "(s) friend got guest's grant"
g peer grants guest remove web
[ "$(web $GUEST)" = BLOCKED ] || fail "(s) guest kept a grant detached from its side"
g grant everyone web on
for src in $GUEST $FRIEND; do [ "$(web $src)" = home-other ] || fail "(s) $src missed the grant for everyone"; done
refused grant rule remove web host:192.168.1.5:8080/udp
refused grant detach web --from friend
refused grant remove web
[ "$(web $FRIEND)" = home-other ] || fail "(s) a refused change took access away"
g grant rename web lan-web
[ "$(web $GUEST)" = home-other ] || fail "(s) a rename changed access"
g grant remove lan-web --force
for src in $GUEST $FRIEND; do [ "$(web $src)" = BLOCKED ] || fail "(s) $src kept a removed grant"; done
[ "$(web $LAPTOP)" = home-other ] || fail "(s) laptop's access changed with others' grants"
[ "$(https_as $GUEST immich.mydomain.com 198.18.1.5)" = home-immich ] || fail "(s) guest lost family"
grep -q '^guest  grants=family  .*address=10.8.0.3 ' <<<"$($P peer show guest)" \
    || { $P peer show guest; fail "(s) guest's grants or address"; }
[ "$($P export guest --platform mobile 2>/dev/null | grep -v '^#')" = "$GUEST_CONF" ] \
    || fail "(s) guest's client config changed with its grants"
pass "(s) grant and peer grants commands change access on return; refused ones change nothing"

echo "ALL PASS"
