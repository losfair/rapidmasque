#!/bin/sh
# Run-time smoke test for a built rapidmasque binary on the target OS (used
# in the OpenBSD VMs to check the cross-built binaries). Brings up a server
# and a client on loopback and tunnels UDP to an echo target, plain, with ECH,
# and (on OpenBSD) with an extra multipath path, with and without its own
# routing table.
# Usage: smoke-test.sh BINARY TOOLS_DIR
# TOOLS_DIR holds udpecho/udpsend/gencert from testing/ built for the target.
set -eu

bin="$1"
tools="$2"
work="$(mktemp -d)"
pids=""
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || true; done
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
"$bin" serve --addr 0.0.0.0:4433 --rules "$work/rules.json" \
    --cert "$work/cert.pem" --key "$work/key.pem" --ech-key "$work/ech.pem" \
    --stats-listen 127.0.0.1:9100 \
    > "$work/server.log" 2>&1 &
server_pid=$!
pids="$pids $server_pid"
sleep 2

# fail MESSAGE CLIENT_PID CLIENT_STATS_PORT CLIENT_LOG: report a failed check
# with what both sides were doing, and exit.
fail() {
    echo "FAIL: $1"
    if [ "$(uname -s)" = OpenBSD ]; then
        echo "--- processes"; ps -o pid,pcpu,state,wchan,command -p "$2,$server_pid" || true
        echo "--- client stats"; ftp -V -o - "http://127.0.0.1:$3/stats" 2>&1 || true
        echo "--- server stats"; ftp -V -o - "http://127.0.0.1:9100/stats" 2>&1 || true
        # Two seconds of both sides' syscalls: a stalled sender shows no
        # sendmsg at all.
        ktrace -f "$work/client.ktrace" -t c -p "$2" || true
        ktrace -f "$work/server.ktrace" -t c -p "$server_pid" || true
        sleep 2
        ktrace -C || true
        for side in client server; do
            echo "--- $side syscalls (2 s)"
            kdump -f "$work/$side.ktrace" > "$work/$side.kdump" 2>/dev/null || true
            awk '$3 == "CALL" { sub(/\(.*/, "", $4); print $4 }' "$work/$side.kdump" |
                sort | uniq -c | sort -rn
            grep -E 'RET +[a-z_]+ -1' "$work/$side.kdump" | sort | uniq -c | sort -rn | head -n 20
        done
        echo "--- udp sockets"; netstat -an -f inet -p udp || true
    fi
    kill "$2" 2>/dev/null || true
    echo "--- server log"; cat "$work/server.log"
    echo "--- client log"; cat "$4"
    exit 1
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
    i=0
    until "$tools/udpsend" "127.0.0.1:$port" "$name" 2>/dev/null | grep -q "echo:$name"; do
        i=$((i + 1))
        [ $i -lt 10 ] || fail "$name" "$cpid" "$stats" "$work/client-$name.log"
        sleep 1
    done
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

# Multipath (OpenBSD): an extra path towards this host's egress address, first
# on the client's main socket, then in routing table 0 (which unprivileged
# processes may select) through a socket of its own. The routing-table path
# must come up and receive replies on that socket. Each client exits right
# after its check, so the server sees connections on several paths close
# while others start: a few rounds of that once caught the server's UDP
# socket stalling for good (fixed in losfair/noq#4: OpenBSD send lock contention).
if [ "$(uname -s)" = OpenBSD ]; then
    egress_ip="$(ifconfig egress 2>/dev/null | awk '/inet /{print $2; exit}')"
    if [ -z "$egress_ip" ]; then
        echo "FAIL: no egress address for the multipath checks"
        ifconfig
        exit 1
    fi
    spec="$egress_ip:4433/rtable=0"
    for round in 1 2 3; do
        check "multipath-$round" 6005 --path "$egress_ip:4433"
        log="$work/client-rtable-$round.log"
        "$bin" client --listen 127.0.0.1:6003 \
            --endpoint https://localhost:4433/connect --proxy-addr 127.0.0.1:4433 \
            --stats-listen 127.0.0.1:7003 \
            --insecure --path "$spec" > "$log" 2>&1 &
        cpid=$!
        pids="$pids $cpid"
        i=0
        until grep -q "multipath path $spec up" "$log" &&
            [ "$(path_rx 7003 "$egress_ip:4433")" -gt 0 ] 2>/dev/null; do
            i=$((i + 1))
            [ $i -le 15 ] || fail "path $spec did not come up and receive (round $round)" \
                "$cpid" 7003 "$log"
            sleep 1
        done
        grep -q "routing table 0: socket" "$log" ||
            fail "no routing-table socket (round $round)" "$cpid" 7003 "$log"
        kill "$cpid" 2>/dev/null || true
        echo "PASS: path in routing table 0 up and receiving (round $round)"
    done
    check rtable 6004 --path "$spec"
fi
