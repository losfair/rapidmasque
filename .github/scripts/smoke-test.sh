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
    > "$work/server.log" 2>&1 &
pids="$pids $!"
sleep 2

# check NAME PORT [CLIENT_ARGS...]: tunnel one datagram through a fresh client.
check() {
    name="$1"
    port="$2"
    shift 2
    "$bin" client --listen "127.0.0.1:$port" \
        --endpoint https://localhost:4433/connect --proxy-addr 127.0.0.1:4433 \
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
    kill "$cpid" 2>/dev/null || true
    if [ -z "$ok" ]; then
        echo "FAIL: $name"
        echo "--- server log"; cat "$work/server.log"
        echo "--- client log"; cat "$work/client-$name.log"
        exit 1
    fi
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
    spec="$egress_ip:4433/rtable=0"
    "$bin" client --listen 127.0.0.1:6003 \
        --endpoint https://localhost:4433/connect --proxy-addr 127.0.0.1:4433 \
        --insecure --path "$spec" > "$work/client-rtable.log" 2>&1 &
    cpid=$!
    pids="$pids $cpid"
    i=0
    until grep -q "multipath path $spec up" "$work/client-rtable.log"; do
        i=$((i + 1))
        if [ $i -gt 10 ]; then
            echo "FAIL: path $spec did not come up"
            echo "--- server log"; cat "$work/server.log"
            echo "--- client log"; cat "$work/client-rtable.log"
            exit 1
        fi
        sleep 1
    done
    grep -q "routing table 0: socket" "$work/client-rtable.log" || {
        echo "FAIL: no routing-table socket"
        cat "$work/client-rtable.log"
        exit 1
    }
    kill "$cpid" 2>/dev/null || true
    check rtable 6004 --path "$spec"
    echo "PASS: path in routing table 0 up"
fi
