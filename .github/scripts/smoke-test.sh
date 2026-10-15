#!/bin/sh
# Run-time smoke test for a built rapidmasque binary on the target OS (used
# in the OpenBSD VMs to check the cross-built binaries). Brings up a server
# and a client on loopback and tunnels UDP to an echo target, plain, with ECH,
# and (on OpenBSD) with an extra multipath path in its own routing table.
# Usage: smoke-test.sh BINARY TOOLS_DIR
# TOOLS_DIR holds udpecho/udpsend/gencert from testing/ built for the target.
set -eu

bin="$1"
tools="$2"
work="$(mktemp -d)"
pids=""
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    [ "$(uname -s)" != OpenBSD ] || sudo -n pkill -x tcpdump 2>/dev/null || true
}
trap cleanup EXIT INT TERM

uname -a
"$bin" --version

"$tools/gencert" "$work/cert.pem" "$work/key.pem" 1 smoke
echo '[{"endpoint":"https://localhost:4433/connect","target":"127.0.0.1:5390"}]' \
    > "$work/rules.json"
"$bin" gen-ech-key --public-name public.example.com > "$work/ech.pem" 2> "$work/ech.err"
ech="$(sed -n 's/.*ech="\([^"]*\)".*/\1/p' "$work/ech.err")"
test -n "$ech"

"$tools/udpecho" 127.0.0.1:5390 > /dev/null 2>&1 &
pids="$pids $!"
RUST_LOG=debug "$bin" serve --addr 0.0.0.0:4433 --rules "$work/rules.json" \
    --cert "$work/cert.pem" --key "$work/key.pem" --ech-key "$work/ech.pem" \
    --stats-listen 127.0.0.1:9100 \
    > "$work/server.log" 2>&1 &
server_pid=$!
pids="$pids $server_pid"
sleep 2

# diagnose PID STATS_PORT: what a stuck client is doing (OpenBSD only).
diagnose() {
    [ "$(uname -s)" = OpenBSD ] || return 0
    echo "--- processes"; ps -o pid,pcpu,state,wchan,command -p "$1,$server_pid" || true
    echo "--- client stats"; ftp -V -o - "http://127.0.0.1:$2/stats" 2>&1 || true
    echo "--- server stats"; ftp -V -o - "http://127.0.0.1:9100/stats" 2>&1 || true
    echo "--- client and server syscalls (2 s)"
    ktrace -f "$work/client-diag.ktrace" -t c -p "$1" || true
    ktrace -f "$work/server-diag.ktrace" -t c -p "$server_pid" || true
    sleep 2
    ktrace -C || true
    for side in client server; do
        echo "--- $side syscalls"
        kdump -f "$work/$side-diag.ktrace" > "$work/$side-diag.txt" 2>/dev/null || true
        awk '$3 == "CALL" { sub(/\(.*/, "", $4); print $4 }' "$work/$side-diag.txt" | sort | uniq -c | sort -rn
        grep -E 'RET +[a-z_]+ -1' "$work/$side-diag.txt" | sort | uniq -c | sort -rn | head -n 20
        grep -E 'sendmsg|recvmsg' "$work/$side-diag.txt" | tail -n 30
    done
    echo "--- udp sockets"; netstat -an -f inet -p udp || true
    echo "--- plain UDP over loopback (to the echo target)"
    "$tools/udpsend" 127.0.0.1:5390 probe 2>&1 || true
    echo "--- interfaces"; netstat -in || true
    echo "--- IP counters"; netstat -s -p ip | grep -i -E 'drop|fail|no route|discard|output|fragment' || true
    echo "--- capture processes"; ps -ax -o pid,stat,command | grep '[t]cpdump' || true
    echo "--- pf"; cat /etc/pf.conf 2>&1 || true
    sudo -n pfctl -si 2>&1 || true
    sudo -n pfctl -sr 2>&1 || true
    echo "states: $(sudo -n pfctl -ss 2>/dev/null | wc -l)"
    sudo -n pfctl -ss 2>&1 | grep -E '4433|5390' | head -n 40 || true
    echo "--- after disabling pf"
    sudo -n pfctl -d 2>&1 || true
    "$tools/udpsend" 127.0.0.1:5390 probe 2>&1 || true
    if [ -n "${port:-}" ]; then
        sleep 5
        "$tools/udpsend" "127.0.0.1:$port" probe 2>&1 || true
    fi
}

# show_logs CLIENT_LOG: the server's and a client's log, plus whatever the
# routing-table check captured.
show_logs() {
    echo "--- server log"; cat "$work/server.log"
    echo "--- client log"; cat "$1"
    for cap in "$work"/tcpdump-*.txt; do
        [ -f "$cap" ] || continue
        echo "--- $(basename "$cap")"; tail -n 100 "$cap"
    done
    if [ -f "$work/server-all.ktrace" ]; then
        echo "--- server: failed syscalls since the multipath rounds began"
        ktrace -C || true
        kdump -f "$work/server-all.ktrace" > "$work/server-all.txt" 2>/dev/null || true
        grep -E 'RET +[a-z_]+ -1' "$work/server-all.txt" | sort | uniq -c | sort -rn | head -n 20
        echo "--- server: first failed sendmsg and what preceded it"
        grep -n -m 1 -E 'RET +sendmsg -1' "$work/server-all.txt" | cut -d: -f1 | while read -r l; do
            sed -n "$((l > 30 ? l - 30 : 1)),$((l + 10))p" "$work/server-all.txt"
        done
        echo "--- server: sendmsg calls per second"
        grep -E 'CALL +sendmsg' "$work/server-all.txt" | wc -l
    fi
    if [ -f "$work/udpstat.before" ]; then
        echo "--- UDP counters, before and now"
        cat "$work/udpstat.before"
        netstat -s -p udp || true
    fi
}

# path_rx STATS_PORT REMOTE: datagrams received on the client's path to REMOTE.
path_rx() {
    ftp -V -o - "http://127.0.0.1:$1/stats" 2>/dev/null | awk -v r="\"remote\": \"$2\"" '
        index($0, r) { f = 1 }
        f && /"udp_rx"/ { g = 1 }
        g && /"datagrams"/ { gsub(/[^0-9]/, ""); print; exit }'
}

# check NAME PORT [CLIENT_ARGS...]: tunnel one datagram through a fresh client.
check() {
    name="$1"
    port="$2"
    shift 2
    stats=$((port + 1000))
    "$bin" client --listen "127.0.0.1:$port" \
        --endpoint https://localhost:4433/connect --proxy-addr 127.0.0.1:4433 \
        --stats-listen "127.0.0.1:$stats" \
        --insecure "$@" > "$work/client-$name.log" 2>&1 &
    cpid=$!
    pids="$pids $cpid"
    ok=""
    i=0
    while [ $i -lt 10 ]; do
        if "$tools/udpsend" "127.0.0.1:$port" "$name" 2>/dev/null | grep -q "echo:$name"; then
            ok=1
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    if [ -z "$ok" ]; then
        echo "FAIL: $name"
        diagnose "$cpid" "$stats"
        kill "$cpid" 2>/dev/null || true
        show_logs "$work/client-$name.log"
        exit 1
    fi
    kill "$cpid" 2>/dev/null || true
    echo "PASS: $name"
}

check plain 6001
check ech 6002 --ech-config "$ech"
grep -q "ech=true" "$work/server.log" || {
    echo "FAIL: server did not report ECH accepted"
    cat "$work/server.log"
    exit 1
}
echo "PASS: ECH accepted on the server"

# Per-path routing table (OpenBSD): an extra path towards this host's egress
# address in routing table 0, which unprivileged processes may select. The
# path must come up through its own socket and the tunnel keep working.
if [ "$(uname -s)" = OpenBSD ]; then
    egress_ip="$(ifconfig egress 2>/dev/null | awk '/inet /{print $2; exit}')"
    if [ -z "$egress_ip" ]; then
        echo "FAIL: no egress address for the routing-table check"
        ifconfig
        exit 1
    fi
    egress_if="$(ifconfig egress | sed -n '1s/:.*//p')"
    for ifc in lo0 "$egress_if"; do
        sudo tcpdump -n -l -i "$ifc" udp port 4433 > "$work/tcpdump-$ifc.txt" 2>&1 &
    done
    netstat -s -p udp > "$work/udpstat.before" 2>&1 || true
    spec="$egress_ip:4433/rtable=0"
    for round in 1 2 3 4 5 6; do
        # The same extra path without a routing table first, to tell
        # multipath problems from routing-table ones.
        check "multipath-$round" 6005 --path "$egress_ip:4433"
        "$bin" client --listen 127.0.0.1:6003 \
            --endpoint https://localhost:4433/connect --proxy-addr 127.0.0.1:4433 \
            --stats-listen 127.0.0.1:7003 \
            --insecure --path "$spec" > "$work/client-rtable-up-$round.log" 2>&1 &
        cpid=$!
        pids="$pids $cpid"
        # The path must come up and receive through its own socket.
        i=0
        until grep -q "multipath path $spec up" "$work/client-rtable-up-$round.log" &&
            [ "$(path_rx 7003 "$egress_ip:4433")" -gt 0 ] 2>/dev/null; do
            i=$((i + 1))
            if [ $i -gt 15 ]; then
                echo "FAIL: path $spec did not come up and receive (round $round)"
                port=6003
                diagnose "$cpid" 7003
                show_logs "$work/client-rtable-up-$round.log"
                exit 1
            fi
            sleep 1
        done
        grep -q "routing table 0: socket" "$work/client-rtable-up-$round.log" || {
            echo "FAIL: no routing-table socket"
            cat "$work/client-rtable-up-$round.log"
            exit 1
        }
        echo "PASS: path in routing table 0 up and receiving after ${i}s (round $round)"
        kill "$cpid" 2>/dev/null || true
    done
    check rtable 6004 --path "$spec"
fi
