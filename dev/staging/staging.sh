#!/usr/bin/env bash
# Parallax staging gateway: the real container on a development machine, routing
# into fake LANs, driven end to end from this script. See README.md.
#
# Usage: sudo dev/staging/staging.sh <command>   (or pkexec with the absolute path)
#   up                         fake LANs, config (first run), build, start the container
#   down                       stop the container and remove the fake LANs (state is kept)
#   reset                      down, then delete the state directory (server key, peers, config)
#   apply                      re-apply the configuration (SIGHUP the container)
#   export                     write the configuration as TOML to $STAGING_STATE/config/export.toml (0600)
#   import FILE                replace the configuration with a TOML file, then re-apply
#   peer NAME TEMPLATE [PLAT]  add a peer (private key kept), re-apply, show its QR
#   qr NAME [PLATFORM]         write $STAGING_STATE/qr/NAME-PLATFORM.png and print the QR
#   smoke                      end-to-end checks from a client namespace through the tunnel
#   status                     container, WireGuard and firewall summary
#   logs                       follow the container log
#
# Environment:
#   STAGING_STATE            state directory (default /var/lib/parallax-staging). Outside the
#                            checkout, so every worktree drives the same gateway with the same keys.
# Read on the first `up`, when the config is rendered:
#   STAGING_ENDPOINT         address clients dial (default: this host's default-route source)
#   STAGING_PORT             WireGuard listen port (default 51814)
#   STAGING_PUBLIC_RESOLVER  where the DNS server sends public names (default: the default-route gateway)
set -euo pipefail
umask 077   # the state directory holds the server key and exported client configs with private keys

DIR="$(cd "$(dirname "$0")" && pwd)"
STATE="$(realpath -m -- "${STAGING_STATE:-/var/lib/parallax-staging}")"
case "$STATE" in /*/*) ;; *) echo "staging: STAGING_STATE must be an absolute path below /, got '$STATE'" >&2; exit 1 ;; esac
export STAGING_STATE="$STATE"   # compose.yml mounts from it
CONFIG="$STATE/config/parallax.toml"
CONTAINER=parallax-staging
GATEWAY=10.9.0.1   # the tunnel gateway address, from the template's supernet 10.9.0.0/16
COMPOSE=(docker compose -f "$DIR/compose.yml")

say() { echo "staging: $*"; }
die() { echo "staging: $*" >&2; exit 1; }
inns() { ip netns exec "$@"; }

[ "$(id -u)" = 0 ] || die "run as root (sudo $0 $*, or pkexec $DIR/staging.sh $*)"

# Recursive chown and rm only ever touch a directory `up` created: it holds this marker.
MARKER="$STATE/.parallax-staging"
if [ -d "$STATE" ] && [ ! -f "$MARKER" ] && [ -n "$(ls -A "$STATE")" ]; then
    die "$STATE is not empty and is not a staging state directory (no $(basename "$MARKER")); check STAGING_STATE"
fi

# Keep the state directory owned by whoever ran sudo or pkexec, so agents and editors can read it
# (QR codes, logs) without root. It stays mode 0700.
CALLER_UID="${SUDO_UID:-${PKEXEC_UID:-}}"   # sudo or pkexec
own_state() {
    [ -n "$CALLER_UID" ] && [ -f "$MARKER" ] || return 0
    chown -R "$CALLER_UID:$(id -g "$CALLER_UID")" "$STATE" || true
}
trap own_state EXIT

# ------------------------------------------------------------------ fake LANs
# lanN: namespace pxs-lanN, host side of the veth pxs-lanN = 192.168.20N.1 (the
# gateway's leg on that LAN), hosts at .5 (and DNS at .53 on lan1).
lan_up() {
    local n=$1 ns=pxs-lan$1 net=192.168.20$1
    ip netns list | grep -qx "$ns\( .*\)\?" && return 0
    ip netns add "$ns"
    inns "$ns" ip link set lo up
    ip link add "$ns" type veth peer name eth0 netns "$ns"
    ip addr add "$net.1/24" dev "$ns"
    ip link set "$ns" up
    inns "$ns" ip addr add "$net.5/24" dev eth0
    inns "$ns" ip link set eth0 up
    # lan1 is routed: its hosts send replies for 10.9.0.0/16 back through the gateway.
    inns "$ns" ip route add default via "$net.1"
    mkdir -p "$STATE/log"
    local name; [ "$n" = 1 ] && name=immich || name=nas
    inns "$ns" setsid -f python3 "$DIR/fakehost.py" "lan$n-$name" "$net.5" 80 \
        >>"$STATE/log/$ns.log" 2>&1 </dev/null
    inns "$ns" setsid -f python3 "$DIR/fakehost.py" "lan$n-other" "$net.5" 8080 \
        >>"$STATE/log/$ns.log" 2>&1 </dev/null
    if [ "$n" = 1 ]; then
        inns "$ns" ip addr add "$net.53/24" dev eth0
        inns "$ns" dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces --listen-address="$net.53" \
            --user=root --pid-file="$STATE/log/$ns-dns.pid" \
            --address=/immich.staging.test/192.168.201.5 \
            --address=/nas.staging.test/192.168.202.5
    fi
}

kill_ns() { # TERM everything in a namespace, then KILL what's left
    ip netns pids "$1" 2>/dev/null | xargs -r kill 2>/dev/null || true
    sleep 0.2
    ip netns pids "$1" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
}

lan_down() {
    local ns=pxs-lan$1
    ip netns list | grep -qx "$ns\( .*\)\?" || return 0
    kill_ns "$ns"
    ip netns del "$ns"
}

# ------------------------------------------------------------------ config
# Rendered once. The container imports it into its database on the first start
# and renames it to parallax.toml.imported; from then on the database is the
# configuration (`staging.sh export` / `import`).
render_config() {
    [ -f "$CONFIG" ] || [ -f "$CONFIG.imported" ] && return 0
    local route wan src gw
    route="$(ip -4 route get 1.1.1.1)"
    wan="$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$route")"
    src="$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<<"$route")"
    gw="$(sed -n 's/.* via \([^ ]*\).*/\1/p' <<<"$route")"
    local endpoint="${STAGING_ENDPOINT:-$src}" port="${STAGING_PORT:-51814}"
    local resolver="${STAGING_PUBLIC_RESOLVER:-${gw:-1.1.1.1}}"
    [ -n "$endpoint" ] && [ -n "$wan" ] || die "cannot work out the default route; set STAGING_ENDPOINT"
    mkdir -p "$STATE/config" "$STATE/out"
    sed -e "s/@WAN@/$wan/" -e "s/@ENDPOINT@/$endpoint/" -e "s/@PORT@/$port/g" \
        -e "s/@PUBLIC_RESOLVER@/$resolver/" "$DIR/parallax.toml.in" >"$CONFIG"
    say "rendered $CONFIG (endpoint $endpoint:$port, wan $wan, public resolver $resolver)"
}

# A value from the rendered file. Only for what staging never changes
# (interface, endpoint), so the copy the container renamed still holds it.
cfg() {
    local file="$CONFIG"; [ -f "$file" ] || file="$CONFIG.imported"
    sed -n "/^$1 *= */{s/^$1 *= *\"\{0,1\}\([^\"]*\)\"\{0,1\}/\1/p;q}" "$file"
}

# ------------------------------------------------------------------ container
running() { [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = true ]; }
px() { docker exec "$CONTAINER" parallax "$@"; }

# Wait until the container has applied the config and started its servers: wg1 up, and
# the DNS server and the HTTPS proxy listening on the gateway address (they start after apply).
wait_applied() {
    local iface; iface="$(cfg interface)"
    for _ in $(seq 1 60); do
        if ip link show "$iface" >/dev/null 2>&1 \
            && ss -Hltn 'sport = :53' | grep -qF "$GATEWAY:53" \
            && ss -Hltn 'sport = :8443' | grep -qF "$GATEWAY:8443"; then
            return 0
        fi
        running || { docker logs --tail 30 "$CONTAINER" >&2; die "container exited"; }
        sleep 0.5
    done
    docker logs --tail 30 "$CONTAINER" >&2
    die "gateway did not come up"
}

# SIGHUP, then wait for the entrypoint's "re-applied" or "re-apply failed" line.
reapply() {
    local pattern='parallax: re-appl\(ied\|y failed\)' before now
    before="$(docker logs "$CONTAINER" 2>&1 | grep -c "$pattern" || true)"
    docker kill -s HUP "$CONTAINER" >/dev/null
    for _ in $(seq 1 60); do
        sleep 0.5
        now="$(docker logs "$CONTAINER" 2>&1 | grep "$pattern" || true)"
        [ "$(grep -c . <<<"$now")" -gt "$before" ] || continue
        if tail -n1 <<<"$now" | grep -q 'failed'; then
            docker logs --tail 20 "$CONTAINER" >&2
            die "re-apply failed"
        fi
        return 0
    done
    die "re-apply did not finish"
}

up() {
    mkdir -p "$STATE"
    chmod 700 "$STATE"
    touch "$MARKER"
    # Always rebuild the fake LANs, so a half-finished earlier `up` can't pass for a good one.
    lan_down 1; lan_down 2
    lan_up 1; lan_up 2
    render_config
    # Docker may be stopped between sessions; starting it here saves a second root prompt.
    systemctl is-active -q docker || systemctl start docker
    if running; then
        reapply
        say "gateway already up; fake LANs rebuilt and config re-applied"
        return 0
    fi
    # Staging uses the same nft table as any Parallax gateway; never take over another one.
    if nft list table inet parallax >/dev/null 2>&1 || ip link show "$(cfg interface)" >/dev/null 2>&1; then
        die "nft table inet parallax or $(cfg interface) already exists: another Parallax gateway runs on this host"
    fi
    "${COMPOSE[@]}" up -d --build
    wait_applied
    say "gateway up: $(cfg endpoint) on $(cfg interface)"
}

down() {
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        "${COMPOSE[@]}" down
    fi
    # The entrypoint removes the nft table and the WireGuard interface; DOCKER-USER
    # rules stay behind (harmless, but remove them so the host is as we found it).
    # Same match as apply.rs: exact comment "parallax", deleted by handle.
    local h
    for h in $(nft -a list chain ip filter DOCKER-USER 2>/dev/null |
               sed -n 's/.*comment "parallax" # handle \([0-9]*\)$/\1/p'); do
        nft delete rule ip filter DOCKER-USER handle "$h" || true
    done
    smoke_cleanup
    lan_down 1
    lan_down 2
    say "down (state kept in $STATE)"
}

has_peer() { px peer show "$1" >/dev/null 2>&1; }

import_config() { # file: copied into the mounted config directory, imported, removed
    running || die "gateway not running (staging.sh up)"
    [ -f "$1" ] || die "no such file: $1"
    install -m 600 "$1" "$STATE/config/import.toml"
    local rc=0
    px config import /etc/parallax/import.toml || rc=$?
    rm -f "$STATE/config/import.toml"
    [ "$rc" = 0 ] || die "import failed; nothing changed"
}

# Adds the peer if it's missing. Callers re-apply afterwards, also when it already
# existed, so a peer saved by an earlier run whose re-apply failed still goes live.
add_peer() { # name template platform
    running || die "gateway not running (staging.sh up)"
    if has_peer "$1"; then
        say "peer $1 already exists"
    else
        px peer add "$1" --template "$2" --platform "$3" --keep-private-key >/dev/null
        say "added peer $1 ($2)"
    fi
}

qr() { # name platform
    mkdir -p "$STATE/qr"
    local png="$STATE/qr/$1-$2.png"
    px export "$1" --platform "$2" 2>/dev/null | qrencode -t png -s 8 -o "$png"
    px export "$1" --platform "$2" 2>/dev/null | qrencode -t ansiutf8
    say "QR for $1 ($2): $png"
}

status() {
    docker ps -a --filter "name=^$CONTAINER\$" --format '{{.Names}}  {{.Status}}'
    local iface; iface="$(cfg interface 2>/dev/null || true)"
    [ -n "$iface" ] && wg show "$iface" 2>/dev/null || say "no WireGuard interface"
    nft list table inet parallax >/dev/null 2>&1 && say "nft table inet parallax present" \
        || say "nft table inet parallax absent"
    ip netns list | grep '^pxs-' || true
}

# ------------------------------------------------------------------ smoke test
# A client namespace on its own veth dials the real endpoint with exported
# configs, so this exercises the same path a phone on the LAN does.
CLIENT=pxs-client
LISTENER=
smoke_cleanup() {
    kill_ns "$CLIENT"
    ip netns del "$CLIENT" 2>/dev/null || true
    [ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null || true
    own_state
}

client_iface() { # peer iface -> brings up iface in $CLIENT from the peer's export
    local tmp="$STATE/smoke/$2.conf"
    mkdir -p "$STATE/smoke"
    px export "$1" --platform linux 2>/dev/null >"$tmp"
    local addr allowed
    addr="$(sed -n 's/^Address *= *//p' "$tmp" | head -n1)"
    allowed="$(sed -n 's/^AllowedIPs *= *//p' "$tmp" | head -n1)"
    ip -n "$CLIENT" link add "$2" type wireguard
    inns "$CLIENT" wg setconf "$2" <(wg-quick strip "$tmp")
    ip -n "$CLIENT" addr add "$addr" dev "$2"
    ip -n "$CLIENT" link set "$2" up
    local net
    for net in ${allowed//,/ }; do ip -n "$CLIENT" route replace "$net" dev "$2"; done
    echo "${addr%/*}"
}

smoke() {
    running || die "gateway not running (staging.sh up)"
    local ok=1
    pass_db() { echo "PASS: $*"; }
    fail_db() { echo "FAIL: $*"; ok=0; }
    add_peer smoke-personal personal linux
    add_peer smoke-guest guest linux
    reapply
    trap 'smoke_cleanup' EXIT
    echo "--- database"
    if [ -f "$CONFIG.imported" ] && [ ! -f "$CONFIG" ]; then pass_db "the first start imported parallax.toml and renamed it"
    else fail_db "config/parallax.toml.imported missing, or parallax.toml still there"; fi
    local before after
    before="$(px config export)"
    px config export -o /etc/parallax/smoke-export.toml 2>/dev/null
    px config import /etc/parallax/smoke-export.toml >/dev/null
    rm -f "$STATE/config/smoke-export.toml"
    after="$(px config export)"
    if [ -n "$before" ] && [ "$before" = "$after" ]; then pass_db "importing the export changes nothing"
    else fail_db "the export changed after importing it"; fi
    smoke_cleanup
    local endpoint port gw
    endpoint="$(cfg endpoint)"; endpoint="${endpoint%:*}"
    gw="$GATEWAY"
    ip netns add "$CLIENT"
    inns "$CLIENT" ip link set lo up
    ip link add "$CLIENT" type veth peer name eth0 netns "$CLIENT"
    ip addr add 192.168.209.1/24 dev "$CLIENT"
    ip link set "$CLIENT" up
    inns "$CLIENT" ip addr add 192.168.209.2/24 dev eth0
    inns "$CLIENT" ip link set eth0 up
    inns "$CLIENT" ip route add "$endpoint/32" via 192.168.209.1
    # Something listening on the gateway host itself, which no tunnel peer may reach.
    port=18099
    python3 "$DIR/fakehost.py" gateway-host 0.0.0.0 "$port" >/dev/null 2>&1 </dev/null &
    LISTENER=$!

    pass() { echo "PASS: $*"; }
    fail() { echo "FAIL: $*"; ok=0; }
    get() { inns "$CLIENT" curl -s --max-time 3 "$@"; }
    resolve() { inns "$CLIENT" dig +short +time=2 +tries=1 @"$gw" "$1" A | tail -n1 || true; }
    status() { inns "$CLIENT" dig +time=2 +tries=1 @"$gw" "$1" A | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
    expect() { # description, expected substring ("" = must be blocked), curl args...
        local d=$1 want=$2 out rc=0; shift 2
        out="$(get "$@")" || rc=$?
        if [ -n "$want" ]; then
            if [[ "$out" == *"$want"* ]]; then pass "$d ($out)"
            else fail "$d: got '${out:-nothing}' (curl exit $rc), wanted '$want'"; fi
        # Blocked means refused (7) or timed out (28); an empty reply or other error is not.
        elif [ "$rc" = 7 ] || [ "$rc" = 28 ]; then pass "$d (blocked, curl exit $rc)"
        else fail "$d: wanted blocked, got curl exit $rc '${out}'"; fi
    }
    # The isolation checks below mean nothing unless the host listener really answers.
    local up=0
    for _ in $(seq 1 20); do
        curl -s --max-time 1 "http://127.0.0.1:$port/" | grep -q gateway-host && { up=1; break; }
        sleep 0.25
    done
    if [ "$up" = 1 ]; then
        pass "gateway host listener answers locally on :$port"
    else
        fail "gateway host listener on :$port is not answering; isolation checks would be vacuous"
    fi

    echo "--- personal"
    local me; me="$(client_iface smoke-personal wgp)"
    expect "lan1 host by mapped IP, routed (sees the tunnel address)" "saw $me" http://198.19.201.5/
    expect "lan2 host by mapped IP, masqueraded (sees the gateway)" "saw 192.168.202.1" http://198.19.202.5/
    expect "lan1 other port" "lan1-other" http://198.19.201.5:8080/
    [ "$(resolve immich.staging.test)" = 198.19.201.5 ] && pass "dns: immich.staging.test -> 198.19.201.5" \
        || fail "dns: immich.staging.test -> '$(resolve immich.staging.test)'"
    [ "$(resolve nas.staging.test)" = 198.19.202.5 ] && pass "dns: nas.staging.test -> 198.19.202.5" \
        || fail "dns: nas.staging.test -> '$(resolve nas.staging.test)'"
    local public; public="$(resolve example.com)"
    [[ "$public" =~ ^[0-9.]+$ ]] && pass "dns: public name for personal (dns.public) -> $public" \
        || fail "dns: example.com for personal -> '$public'"
    expect "by name through the DNS server" "lan1-immich" --resolve "immich.staging.test:80:$(resolve immich.staging.test)" \
        http://immich.staging.test/
    if inns pxs-lan1 ping -c1 -W2 "$me" >/dev/null 2>&1; then pass "lan1 host starts a connection to the peer (routed)"
    else fail "lan1 host cannot ping the peer at $me"; fi
    expect "gateway host service through the tunnel" "" "http://$gw:$port/"
    ip -n "$CLIENT" link del wgp

    echo "--- guest"
    me="$(client_iface smoke-guest wgg)"
    expect "granted service" "lan1-immich" http://198.19.201.5/
    # The guest's only grant is a service without hostnames: no names, and dns.public is off.
    for name in immich.staging.test nas.staging.test example.com; do
        [ "$(status "$name")" = REFUSED ] && pass "dns: $name refused to the guest" \
            || fail "dns: $name for the guest: '$(status "$name")', wanted REFUSED"
    done
    # Widen the client's routes: the gateway, not the client config, must enforce the grant.
    inns "$CLIENT" wg set wgg peer "$(inns "$CLIENT" wg show wgg peers | head -n1)" allowed-ips 0.0.0.0/0
    ip -n "$CLIENT" route replace 198.19.0.0/16 dev wgg
    ip -n "$CLIENT" route replace 10.9.0.0/16 dev wgg
    expect "other port on the granted host" "" http://198.19.201.5:8080/
    expect "lan2" "" http://198.19.202.5/
    expect "gateway host service" "" "http://$gw:$port/"
    ip -n "$CLIENT" link del wgg

    [ "$ok" = 1 ] && { echo "SMOKE PASS"; return 0; }
    echo "SMOKE FAIL"; return 1
}

# ------------------------------------------------------------------ main
cmd="${1:-}"; shift || true
case "$cmd" in
    up) up ;;
    down) down ;;
    reset) down; [ -f "$MARKER" ] && rm -rf "$STATE"; "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; say "state removed" ;;
    apply) reapply; say "re-applied" ;;
    export)
        running || die "gateway not running (staging.sh up)"
        px config export -o /etc/parallax/export.toml >/dev/null 2>&1
        say "wrote $STATE/config/export.toml"
        ;;
    import) [ $# -ge 1 ] || die "usage: staging.sh import FILE"; import_config "$1"; reapply; say "imported and re-applied" ;;
    peer)
        [ $# -ge 2 ] || die "usage: staging.sh peer NAME TEMPLATE [PLATFORM]"
        add_peer "$1" "$2" "${3:-mobile}"
        reapply
        qr "$1" "${3:-mobile}"
        ;;
    qr) [ $# -ge 1 ] || die "usage: staging.sh qr NAME [PLATFORM]"; qr "$1" "${2:-mobile}" ;;
    smoke) smoke ;;
    status) status ;;
    logs) docker logs -f "$CONTAINER" ;;
    *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
