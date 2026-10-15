#!/usr/bin/env bash
# tc netem testbed: real TCP (iperf3) inside WireGuard (wireguard-go) inside a
# rapidmasque tunnel, between two network namespaces whose link is shaped with
# netem (rate, one-way delay, random loss, bottleneck buffer). It measures what
# the tunnel does to the traffic it carries: TCP goodput and retransmits, and
# the latency a concurrent ping sees under that load.
#
#   ns rmq-c                                        ns rmq-s
#   iperf3 -c / ping -> wgc 10.99.0.1               wgs 10.99.0.2 <- iperf3 -s
#     wireguard-go -> 127.0.0.1:51821                 wireguard-go :51820
#     rapidmasque client  10.10.1.1 <====> 10.10.1.2  rapidmasque serve
#                         (netem on both egresses)
#
# Every scenario (link shape) runs with every variant (rapidmasque flags,
# applied to both ends), and a Markdown report is written to OUT_DIR.
#
# Usage: sudo testing/netem/netem-bench.sh [OUT_DIR]
#
# Environment:
#   RAPIDMASQUE   rapidmasque binary (default: target/release/rapidmasque)
#   WIREGUARD_GO  wireguard-go binary (default: wireguard-go on PATH)
#   GENCERT       testing/gencert.go binary (default: built with go)
#   DURATION      seconds of load per run (default 20)
#   SCENARIOS     subset of: hirtt hirtt-loss lowrtt (default: all)
#   VARIANTS      subset of: default no-aqm cc-none (default: all)
#   DIRECTIONS    subset of: download upload (default: download)
#   REPEATS       runs per cell; the report shows medians (default 1)
#   BUF_MS        bottleneck buffer beyond the delay line, in ms at line rate
#                 (default 100)
#   ALLOW_TBF=1   where the kernel has no netem, shape with tbf instead (rate
#                 and buffer only: delay and loss are ignored). For developing
#                 the harness, not for results.
#
# Needs root, iproute2 (ip, tc), ethtool, iperf3, ping, wg (wireguard-tools),
# curl and python3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/target/netem}"
RAPIDMASQUE="${RAPIDMASQUE:-$ROOT/target/release/rapidmasque}"
WIREGUARD_GO="${WIREGUARD_GO:-$(command -v wireguard-go || true)}"
DURATION="${DURATION:-20}"
SCENARIOS="${SCENARIOS:-hirtt hirtt-loss lowrtt}"
VARIANTS="${VARIANTS:-default no-aqm cc-none}"
DIRECTIONS="${DIRECTIONS:-download}"
REPEATS="${REPEATS:-1}"
BUF_MS="${BUF_MS:-100}"

NSC=rmq-c
NSS=rmq-s
WORK="$(mktemp -d)"
PIDS=()
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# name: rate (Mbit/s) one-way delay (ms) loss (%)
scenario() {
    case "$1" in
        hirtt) echo "20 135 0" ;;      # 270 ms RTT, e.g. a far-away proxy
        hirtt-loss) echo "20 135 1" ;; # the same with 1% random loss each way
        lowrtt) echo "50 10 0" ;;      # 20 ms RTT
        *) echo "unknown scenario $1" >&2; exit 2 ;;
    esac
}

# name: rapidmasque flags for both ends
variant() {
    case "$1" in
        default) echo "" ;;
        no-aqm) echo "--datagram-queue-target-ms 0 --datagram-queue-max-ms 0" ;;
        cc-none) echo "--congestion-control none" ;;
        *) echo "unknown variant $1" >&2; exit 2 ;;
    esac
}

stop_procs() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
    PIDS=()
}
cleanup() {
    stop_procs
    ip netns pids "$NSC" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$NSS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
    ip netns del "$NSS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

nsc() { ip netns exec "$NSC" "$@"; }
nss() { ip netns exec "$NSS" "$@"; }
# bg NS CMD...: start CMD in namespace NS in the background. `ip netns exec`
# execs CMD, so the recorded PID is CMD's own and stop_procs really stops it.
bg() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@" &
    PIDS+=($!)
}

for tool in ip tc ethtool iperf3 ping wg curl python3; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
[ -x "$RAPIDMASQUE" ] || { echo "no rapidmasque binary at $RAPIDMASQUE" >&2; exit 1; }
[ -n "$WIREGUARD_GO" ] && [ -x "$WIREGUARD_GO" ] || { echo "set WIREGUARD_GO" >&2; exit 1; }
if [ -z "${GENCERT:-}" ]; then
    GENCERT="$WORK/gencert"
    GO111MODULE=off go build -o "$GENCERT" "$ROOT/testing/gencert.go"
fi

echo "== topology =="
cleanup_ns() { ip netns del "$NSC" 2>/dev/null || true; ip netns del "$NSS" 2>/dev/null || true; }
cleanup_ns
ip netns add "$NSC"
ip netns add "$NSS"
nsc ip link set lo up
nss ip link set lo up
ip link add rmq-c1 netns "$NSC" type veth peer name rmq-s1 netns "$NSS"
nsc ip addr add 10.10.1.1/24 dev rmq-c1
nss ip addr add 10.10.1.2/24 dev rmq-s1
nsc ip link set rmq-c1 up
nss ip link set rmq-s1 up
# netem shapes whole skbs: with segmentation offloads a 64 KB GSO burst would
# count as one packet.
for dev in rmq-c1 rmq-s1; do
    ns=$NSC; [ "$dev" = rmq-s1 ] && ns=$NSS
    ip netns exec "$ns" ethtool -K "$dev" gso off gro off tso off tx-udp-segmentation off \
        >/dev/null 2>&1 || true
done

if nsc tc qdisc replace dev rmq-c1 root netem delay 1ms 2>/dev/null; then
    SHAPER=netem
elif [ "${ALLOW_TBF:-}" = 1 ]; then
    SHAPER=tbf
    echo "WARNING: no netem in this kernel; shaping rate only with tbf (no delay or loss)"
else
    echo "no netem qdisc (load sch_netem, or ALLOW_TBF=1 for rate-only development runs)" >&2
    exit 1
fi

# shape NS DEV RATE_MBIT DELAY_MS LOSS_PCT: the egress of DEV.
shape() {
    local ns=$1 dev=$2 rate=$3 delay=$4 loss=$5
    local bytes_per_ms=$((rate * 1000 / 8))
    # netem's limit counts the packets in its delay line too.
    local inflight=$((bytes_per_ms * delay / 1400))
    local buf=$((bytes_per_ms * BUF_MS / 1400))
    if [ "$SHAPER" = netem ]; then
        ip netns exec "$ns" tc qdisc replace dev "$dev" root netem \
            rate "${rate}mbit" delay "${delay}ms" loss "${loss}%" limit $((inflight + buf + 10))
    else
        ip netns exec "$ns" tc qdisc replace dev "$dev" root tbf \
            rate "${rate}mbit" burst 32kb limit $((bytes_per_ms * BUF_MS + 32768))
    fi
}

echo "== certificates, WireGuard =="
"$GENCERT" "$WORK/cert.pem" "$WORK/key.pem" 1 netem >/dev/null
echo '[{"endpoint":"https://localhost:4433/wg","target":"127.0.0.1:51820"}]' > "$WORK/rules.json"
wg genkey > "$WORK/c.key"
wg genkey > "$WORK/s.key"
wg pubkey < "$WORK/c.key" > "$WORK/c.pub"
wg pubkey < "$WORK/s.key" > "$WORK/s.pub"

# wireguard-go control sockets live in the shared /var/run/wireguard, so the
# two interfaces need distinct names.
bg "$NSS" "$WIREGUARD_GO" -f wgs > "$OUT/wireguard-go-server.log" 2>&1
bg "$NSC" "$WIREGUARD_GO" -f wgc > "$OUT/wireguard-go-client.log" 2>&1
for _ in $(seq 50); do
    nss ip link show wgs >/dev/null 2>&1 && nsc ip link show wgc >/dev/null 2>&1 && break
    sleep 0.1
done
WG_WIRE=("${PIDS[@]}")
PIDS=()
nss wg set wgs private-key "$WORK/s.key" listen-port 51820 \
    peer "$(cat "$WORK/c.pub")" allowed-ips 10.99.0.1/32
nsc wg set wgc private-key "$WORK/c.key" \
    peer "$(cat "$WORK/s.pub")" allowed-ips 10.99.0.2/32 endpoint 127.0.0.1:51821 \
    persistent-keepalive 5
nss ip addr add 10.99.0.2/24 dev wgs
nsc ip addr add 10.99.0.1/24 dev wgc
# The production setup: WireGuard at MTU 1280 inside the tunnel.
nss ip link set wgs mtu 1280 up
nsc ip link set wgc mtu 1280 up

nss iperf3 -s -B 10.99.0.2 >/dev/null 2>&1 &
IPERF_PID=$!

# run SCENARIO VARIANT DIRECTION REPEAT: one measurement, in $OUT/<name>/.
run() {
    local scen=$1 var=$2 dir=$3 rep=$4
    local name="$scen.$var.$dir.r$rep" flags
    local d="$OUT/$name"
    rm -rf "$d"
    mkdir -p "$d"
    flags=$(variant "$var")
    read -r rate delay loss <<< "$(scenario "$scen")"
    shape "$NSC" rmq-c1 "$rate" "$delay" "$loss"
    shape "$NSS" rmq-s1 "$rate" "$delay" "$loss"

    # shellcheck disable=SC2086
    bg "$NSS" "$RAPIDMASQUE" serve --addr 0.0.0.0:4433 --rules "$WORK/rules.json" \
        --cert "$WORK/cert.pem" --key "$WORK/key.pem" --stats-listen 127.0.0.1:9100 \
        $flags > "$d/server.log" 2>&1
    sleep 0.5
    # shellcheck disable=SC2086
    bg "$NSC" "$RAPIDMASQUE" client --listen 127.0.0.1:51821 \
        --endpoint https://localhost:4433/wg --proxy-addr 10.10.1.2:4433 --insecure \
        --stats-listen 127.0.0.1:9101 $flags > "$d/client.log" 2>&1

    local up=""
    for _ in $(seq 30); do
        if nsc ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; then up=1; break; fi
    done
    local alive=1
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null || alive=""; done
    if [ -z "$up" ] || [ -z "$alive" ]; then
        echo "FAIL: $name: tunnel not up (see $d/server.log, $d/client.log)"
        stop_procs
        return 1
    fi

    nsc ping -i 0.2 -c 15 10.99.0.2 > "$d/ping-idle.txt" 2>&1 || true
    local rev=()
    [ "$dir" = download ] && rev=(-R)
    nsc iperf3 -c 10.99.0.2 -t "$DURATION" -J "${rev[@]}" > "$d/iperf.json" 2>&1 &
    local iperf=$!
    # Latency under load, once TCP is past slow start.
    sleep 3
    nsc ping -i 0.1 -w $((DURATION - 4)) 10.99.0.2 > "$d/ping-load.txt" 2>&1 || true
    wait "$iperf" || true
    nss curl -s http://127.0.0.1:9100/stats > "$d/stats-server.json" || true
    nsc curl -s http://127.0.0.1:9101/stats > "$d/stats-client.json" || true
    stop_procs
    printf '%s %s %s %s %s %s\n' "$scen" "$var" "$dir" "$rate" "$delay" "$loss" > "$d/meta.txt"
    echo "done: $name"
}

echo "== runs ($SHAPER, ${DURATION}s each) =="
failed=0
# Repeats run as whole rounds, so slow drift on the runner spreads over all
# cells instead of biasing one.
for rep in $(seq "$REPEATS"); do
    for scen in $SCENARIOS; do
        for var in $VARIANTS; do
            for dir in $DIRECTIONS; do
                run "$scen" "$var" "$dir" "$rep" || failed=$((failed + 1))
            done
        done
    done
done
kill "$IPERF_PID" 2>/dev/null || true
for p in "${WG_WIRE[@]}"; do kill "$p" 2>/dev/null || true; done

python3 "$ROOT/testing/netem/report.py" "$OUT" "$SHAPER" | tee "$OUT/report.md"
if [ "$failed" -gt 0 ]; then
    echo "$failed run(s) failed" >&2
    exit 1
fi
