#!/bin/sh
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${XUNARA_CLIENT_BINARY:-$root/target/release/xunara-client}
fixture=${XUNARA_COMPAT_FIXTURE:-$root/target/compat-fixture}
command -v nft >/dev/null || { echo 'The network regression test requires nftables for an isolated one-way UDP drop' >&2; exit 1; }
if [ "${1:-}" != --inside ]; then
    [ -x "$binary" ] && [ -x "$fixture" ] || { echo 'Build release binary and tests/compat fixture first' >&2; exit 1; }
    exec unshare --user --map-root-user --net --mount sh "$0" --inside
fi

directory=$(mktemp -d)
snat=${XUNARA_TEST_SNAT:-false}
case "$snat" in true|false) ;; *) echo 'Invalid XUNARA_TEST_SNAT' >&2; exit 1;; esac
pids=''
cleanup() {
    for process in $pids; do kill "$process" 2>/dev/null || :; done
    for process in $pids; do wait "$process" 2>/dev/null || :; done
    printf 'Private test logs: %s\n' "$directory"
}
trap cleanup EXIT INT TERM
ip link set lo up
ip link add testbridge type bridge
ip address add 10.77.0.1/24 dev testbridge
ip link set testbridge up
namespaces=''
for name in router client lan; do
    unshare --net sleep 600 & process=$!
    pids="$pids $process"
    case "$name" in router) router=$process;; client) client=$process;; lan) lan=$process;; esac
    namespaces="$namespaces $process"
done
sleep 0.3
for name in router client; do
    case "$name" in router) process=$router; address=10.77.0.2;; client) process=$client; address=10.77.0.3;; esac
    ip link add "v_$name" type veth peer name uplink netns "$process"
    ip link set "v_$name" master testbridge
    ip link set "v_$name" up
    nsenter -t "$process" -n ip link set lo up
    nsenter -t "$process" -n ip link set uplink up
    nsenter -t "$process" -n ip address add "$address/24" dev uplink
done
ip link add router_lan type veth peer name lan_in
ip link set router_lan netns "$router"
ip link set lan_in netns "$lan"
nsenter -t "$router" -n ip address add 192.168.90.1/24 dev router_lan
nsenter -t "$router" -n ip link set router_lan up
nsenter -t "$router" -n sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
nsenter -t "$lan" -n ip link set lo up
nsenter -t "$lan" -n ip address add 192.168.90.2/24 dev lan_in
nsenter -t "$lan" -n ip link set lan_in up
if [ "$snat" = false ]; then nsenter -t "$lan" -n ip route add 100.80.0.0/24 via 192.168.90.1; fi

"$fixture" -mode fixture -dir "$directory" >"$directory/fixture.log" 2>&1 & pids="$pids $!"
for process in $$ $router $client; do
    nsenter -t "$process" -n "$fixture" -mode proxy -listen 127.0.0.1:18080 -target 10.77.0.1:8080 >"$directory/proxy-control-$process.log" 2>&1 & pids="$pids $!"
    nsenter -t "$process" -n "$fixture" -mode proxy -listen 127.0.0.1:18081 -target 10.77.0.1:8081 >"$directory/proxy-derp-$process.log" 2>&1 & pids="$pids $!"
done
attempt=0
until [ -s "$directory/auth-key" ]; do attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || exit 1; sleep 0.1; done
mkdir -m 700 "$directory/router" "$directory/client"
cat >"$directory/router.json" <<EOF
{"server":"http://127.0.0.1:18080","state_dir":"$directory/router","hostname":"rust-router","interface":"xunara0","listen":"0.0.0.0:41641","advertise_routes":["192.168.90.0/24"],"snat":$snat}
EOF
cat >"$directory/client.json" <<EOF
{"server":"http://127.0.0.1:18080","state_dir":"$directory/client","hostname":"rust-client","interface":"xunara0","listen":"0.0.0.0:41641","accept_routes":true}
EOF
for name in router client; do
    case "$name" in router) process=$router;; client) process=$client;; esac
    nsenter -t "$process" -n "$binary" run --config "$directory/$name.json" --auth-key-file "$directory/auth-key" >"$directory/$name.log" 2>&1 & daemon=$!
    pids="$pids $daemon"
    if [ "$name" = router ]; then router_daemon=$daemon; fi
done
for process in $router $lan; do
    nsenter -t "$process" -n "$fixture" -mode http -listen 0.0.0.0:8088 >"$directory/http-$process.log" 2>&1 & pids="$pids $!"
done
nsenter -t "$router" -n "$fixture" -mode http -listen 0.0.0.0:8089 >"$directory/denied-http.log" 2>&1 & pids="$pids $!"
get_node() { curl --noproxy '*' --max-time 3 -fsS "http://127.0.0.1:18080/_test/node?host=$1"; }
attempt=0
until get_node rust-router >"$directory/router-node.json" 2>/dev/null && get_node rust-client >"$directory/client-node.json" 2>/dev/null; do
    attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || exit 1; sleep 0.2
done
router_ip=$(sed -n 's/.*"ipv4":"\([^"]*\)".*/\1/p' "$directory/router-node.json")
client_ip=$(sed -n 's/.*"ipv4":"\([^"]*\)".*/\1/p' "$directory/client-node.json")
fetch() { nsenter -t "$client" -n curl --noproxy '*' --max-time 3 -fsS "$1"; }
attempt=0
until [ "$(fetch "http://$router_ip:8088" 2>/dev/null || :)" = xunara-core-ok ]; do
    attempt=$((attempt+1)); [ "$attempt" -lt 30 ] || exit 1; sleep 1
done
printf 'PASS Rust TS2021 registration + encrypted TCP\n'
if fetch "http://$router_ip:8089" >/dev/null 2>&1; then echo 'ACL unexpectedly allowed denied port' >&2; exit 1; fi
printf 'PASS denied ACL port\n'
nsenter -t "$client" -n ping -c 2 -W 2 "$router_ip" >"$directory/ping.log"
printf 'PASS encrypted ICMP\n'
curl --noproxy '*' -fsS -X POST http://127.0.0.1:18080/_test/approve >"$directory/approve.json"
attempt=0
until [ "$(fetch http://192.168.90.2:8088 2>/dev/null || :)" = xunara-core-ok ]; do
    attempt=$((attempt+1)); [ "$attempt" -lt 30 ] || exit 1; sleep 1
done
printf 'PASS approved subnet forwarding to independent LAN namespace\n'
if [ "$snat" = true ]; then printf 'PASS subnet SNAT without a LAN return route\n'; fi
"$fixture" -mode official -dir "$directory" -target "$router_ip" >"$directory/official.log" 2>&1 & pids="$pids $!"
attempt=0
until [ -s "$directory/official-ok" ]; do attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || exit 1; sleep 0.5; done
printf 'PASS official Go tsnet to Rust peer\n'
get_node official-peer >"$directory/official-node.json"
official_ip=$(sed -n 's/.*"ipv4":"\([^"]*\)".*/\1/p' "$directory/official-node.json")
attempt=0
until [ "$(fetch "http://$official_ip:8088" 2>/dev/null || :)" = official-core-ok ]; do
    attempt=$((attempt+1)); [ "$attempt" -lt 30 ] || exit 1; sleep 1
done
printf 'PASS Rust to official Go tsnet peer\n'
[ "$(fetch "http://$router_ip:8088" 2>/dev/null || :)" = xunara-core-ok ] || exit 1
nsenter -t "$router" -n nft create table inet xunara_test_oneway
nsenter -t "$router" -n nft add chain inet xunara_test_oneway output '{ type filter hook output priority 0; policy accept; }'
nsenter -t "$router" -n nft add rule inet xunara_test_oneway output meta l4proto udp counter drop
started=$(date +%s)
deadline=$((started + 15))
until [ "$(fetch "http://$router_ip:8088" 2>/dev/null || :)" = xunara-core-ok ]; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo 'DERP fallback failed with one-way UDP; incoming packets must not renew an unverified return path' >&2; exit 1; }
    sleep 0.2
done
printf 'PASS one-way UDP: encrypted TCP recovers through DERP in %ss without trusting incoming-only reachability\n' "$(($(date +%s) - started))"
nsenter -t "$router" -n nft list table inet xunara_test_oneway >"$directory/oneway-firewall.log"
grep -Eq 'counter packets [1-9][0-9]* bytes' "$directory/oneway-firewall.log" || { echo 'One-way UDP test did not drop any packets' >&2; exit 1; }
nsenter -t "$router" -n nft delete table inet xunara_test_oneway
nsenter -t "$client" -n ping -c 2 -W 2 "$router_ip" >"$directory/ping-after-one-way.log"
for process in $router $client; do
    nsenter -t "$process" -n ip rule add priority 50 ipproto udp blackhole
done
sleep 30
[ "$(fetch "http://$router_ip:8088" 2>/dev/null || :)" = xunara-core-ok ] || { echo 'DERP fallback failed while UDP was blocked' >&2; exit 1; }
printf 'PASS UDP blocked: encrypted TCP falls back to certificate-pinned DERP\n'
if [ "${XUNARA_TEST_UNREACHABLE_DERP:-false}" = true ]; then
    for name in rust-router rust-client; do
        get_node "$name" >"$directory/$name-home.json"
        grep -q '"home_derp":"900"' "$directory/$name-home.json" || { echo 'Client advertised an unreachable first DERP region instead of the connected relay' >&2; exit 1; }
    done
    printf 'PASS unreachable first DERP: both Rust nodes advertise the authenticated live relay\n'
fi
for process in $router $client; do
    nsenter -t "$process" -n ip rule del priority 50 ipproto udp blackhole
done
nsenter -t "$client" -n ping -c 2 -W 2 "$router_ip" >"$directory/ping-recovered.log"
printf 'PASS traffic recovers after UDP restored\n'
if [ "$snat" = true ]; then
    kill -TERM "$router_daemon"
    wait "$router_daemon"
    remaining=''
    for process in $pids; do if [ "$process" != "$router_daemon" ]; then remaining="$remaining $process"; fi; done
    pids=$remaining
    if nsenter -t "$router" -n nft list table inet xunara_xunara0 >/dev/null 2>&1; then
        echo 'Graceful stop left its NAT table behind' >&2; exit 1
    fi
    nsenter -t "$router" -n nft create table inet xunara_xunara0
    nsenter -t "$router" -n nft add chain inet xunara_xunara0 preserve_existing
    set +e
    timeout 20 nsenter -t "$router" -n "$binary" run --config "$directory/router.json" >"$directory/collision.log" 2>&1
    status=$?
    set -e
    [ "$status" = 1 ] || { echo 'Existing NAT table was not rejected' >&2; exit 1; }
    nsenter -t "$router" -n nft list table inet xunara_xunara0 | grep -q preserve_existing
    nsenter -t "$router" -n nft delete table inet xunara_xunara0
    printf 'PASS graceful NAT cleanup, persistent identity, and preservation of existing tables\n'
fi
printf 'ALL CORE INTEGRATION CHECKS PASSED\n'
