# rapidmasque

A **multipath MASQUE / CONNECT-UDP** proxy and client written in Rust, built on
[`tokio`](https://tokio.rs), [`noq`](https://github.com/n0-computer/noq) (QUIC;
n0's quinn fork with multipath and BBRv3, used from the
[losfair/noq](https://github.com/losfair/noq) fork for path priorities) and
[`boring`](https://github.com/cloudflare/boring) (BoringSSL). It implements the
CONNECT-UDP protocol of [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) and
supports **TLS certificate hot reload**, **Encrypted Client Hello (ECH)** on
both the server (termination) and client (offering), **QUIC multipath**, and
**BBRv3** congestion control (optionally none, for already congestion-controlled
payloads)
(QUIC multipath is [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/).)

It is functionally aligned with
[zeromasque](https://github.com/losfair/zeromasque) — same CLI, rule table, ECH
key format and behavior — with these differences:

| | zeromasque | rapidmasque |
|---|---|---|
| Runtime | monoio (io_uring / kqueue) | tokio (multi-threaded) |
| QUIC | quiche | noq |
| Congestion control | BBRv2 | BBRv3 per path by default; `none` opt-in |
| Multipath | no | yes (`client --path`, with path priorities) |
| SIGHUP hot reload | Linux only | every Unix |

TLS stays on BoringSSL: rustls (noq's stock backend) cannot terminate ECH, so
rapidmasque plugs BoringSSL's QUIC handshake API into noq's crypto traits
(`src/tls/`). HTTP/3 is a small purpose-built layer (`src/h3.rs`, static-table
QPACK in `src/qpack.rs`).

It interoperates with [masque-go](https://github.com/quic-go/masque-go), the
quic-go reference implementation, in both directions.

## Build

```
cargo build --release
```

The first build compiles BoringSSL from source (via `boring-sys`, which needs
`cmake` and Go), so it takes a few minutes.

Prebuilt binaries are attached to each [GitHub release](https://github.com/losfair/rapidmasque/releases)
(published by CI when a tag is pushed) for:

| Platform | Archive |
|---|---|
| Linux amd64 (static, musl) | `rapidmasque-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (static, musl) | `rapidmasque-aarch64-unknown-linux-musl.tar.gz` |
| macOS arm64 | `rapidmasque-aarch64-apple-darwin.tar.gz` |
| OpenBSD amd64 | `rapidmasque-x86_64-unknown-openbsd.tar.gz` |
| OpenBSD arm64 | `rapidmasque-aarch64-unknown-openbsd.tar.gz` |

The Linux binaries are fully static and run on any distribution; they are built
natively inside Alpine (`.github/scripts/build-musl.sh`). The OpenBSD 7.9
binaries are cross-built on Linux (`.github/scripts/cross-openbsd.sh`: nightly
Rust with `-Zbuild-std`, the official OpenBSD sysroot sets, clang/lld) and then
smoke-tested in OpenBSD VMs (`.github/scripts/smoke-test.sh`); releases wait for
the amd64 test, while the much slower emulated arm64 test runs on every push but
does not gate a release. `SHA256SUMS` covers all archives.

To cross-build OpenBSD locally (needs clang >= 22, cmake, Go, rustup):

```
CLANG=clang-22 CLANGXX=clang++-22 .github/scripts/cross-openbsd.sh arm64 out/rapidmasque
```

## Model

The forwarding **target is pinned on the server** — clients cannot choose a
destination. The server loads a **rule table** mapping endpoints to targets, and
the rule authorities also define the allowed TLS SNI hostnames. Connections with
missing or non-matching SNI are rejected during the TLS handshake; accepted
CONNECT-UDP requests are then matched on `:authority` + path (the query string
is ignored, so generic MASQUE clients that carry `target_host`/`target_port` in
the query still interoperate; the server ignores those and uses the rule's
target).

The **client is a local UDP proxy**: it binds a UDP socket and tunnels every
datagram received there through the proxy, opening one CONNECT-UDP flow per local
source address and relaying replies back.

## Usage

Write a rule table (`rules.json`) mapping endpoints to pinned targets:

```json
[
  {"endpoint": "https://dns.example:4433/connect", "target": "192.0.2.10:53"},
  {"endpoint": "https://ntp.example:4433/connect", "target": "192.0.2.20:123", "idle_timeout": 60}
]
```

Each rule may set `"idle_timeout": N` (seconds, default `35`, `0` disables it): the
server closes a tunnelled UDP flow that has had no traffic in either direction for
that long. A later datagram from the same local source simply reopens a fresh
flow, so this bounds per-flow sockets/tasks and frees QUIC streams for reuse.

Run the proxy:

```
rapidmasque serve \
  --addr 0.0.0.0:4433 \
  --rules rules.json \
  --cert cert.pem --key key.pem
```

Run the client as a local UDP proxy on `127.0.0.1:5353`, pointed at one endpoint:

```
rapidmasque client \
  --endpoint 'https://dns.example:4433/connect' \
  --listen 127.0.0.1:5353
```

Anything sent to `127.0.0.1:5353` is now tunnelled to `192.0.2.10:53`:

```
dig @127.0.0.1 -p 5353 example.com
```

`--proxy-addr <ip:port>` overrides the UDP address to connect to while keeping
the endpoint host as SNI / `:authority` (useful when the host resolves to an
address the proxy isn't bound to, e.g. `localhost` → `::1`).

The client verifies the proxy's certificate against the system trust store by
default; pass `--ca <pem>` to add a CA, or `--insecure` to skip verification
(testing only).

### Transparent forwarding (Linux only)

A rule with `"transparent": true` forwards to its target with the client's
**external source IP preserved** via `IP_TRANSPARENT`, so a local target service
sees traffic as coming from the real client rather than the proxy:

```json
[{"endpoint": "https://proxy:4433/dns", "target": "127.0.0.1:53", "transparent": true}]
```

This requires `CAP_NET_ADMIN`, and the operator must route the target's replies
(addressed to the spoofed client source) back to the proxy — straightforward when
the target is a local service. The source port is the client's QUIC port where
free, else an ephemeral port on the same IP (a client multiplexes many flows over
one address). Non-transparent rules use an ordinary ephemeral source.

A rule may also set `"fwmark": N` to apply `SO_MARK` to the target socket (Linux,
needs `CAP_NET_ADMIN`), e.g. to drive policy routing for the reply path:

```json
[{"endpoint": "https://proxy:4433/dns", "target": "127.0.0.1:53", "transparent": true, "fwmark": 100}]
```

### Congestion control

By default each side sends under **BBRv3**, one instance per multipath path.
BBRv3 is model-based, tolerates non-congestive loss and paces, which suits a
tunnel over a high-RTT, sporadically lossy path far better than a loss-based
controller like CUBIC.

Each new path starts BBRv3 with a 64 KiB congestion window
(`--bbr3-initial-window BYTES`, on `serve` and `client`), not noq's default
12 KB (RFC 9002's ~10 packets): the tunnel is one long-lived connection
carrying aggregated, mostly unreliable traffic, often over high RTT, and from
12 KB BBRv3's startup needs about 6 round trips (~1.7 s at 270 ms) to fill a
20 Mbit/s path while datagrams queue. Startup is paced, so the larger window
is not sent as one burst; lower it for slow, shallow-buffered links.

When the tunnelled traffic already runs its own congestion control end to end
(e.g. TCP inside WireGuard inside the tunnel), an outer controller on top
("double CC") can fight it: the outer window queues and delays datagrams,
inflating the RTT the inner protocol sees, and both react to the same loss.
`--congestion-control none` (on `serve` and/or `client`) removes outer
congestion control: the QUIC connection never holds a datagram back for a
congestion window or pacer and leaves rate control to the tunnelled traffic,
much like plain WireGuard over UDP. Each side controls what it sends: the
server's flag governs proxy → client, the client's flag client → proxy, so set
it on both ends for both directions.

noq applies the window per packet, not per frame, so with `none` the tiny
HTTP/3 control and request-stream traffic is not rate-limited either; it stays
reliable, since loss detection and retransmission keep running. ACKs, RTT
estimation and MTU discovery are unaffected.

#### Datagram queue management

Tunnelled datagrams that arrive faster than the paths carry wait in the QUIC
connection's send buffer. Without management, a tunnelled TCP flow (e.g.
CUBIC inside WireGuard) keeps speeding up until it sees loss, and the only
loss would be the 4 MiB buffer overflowing: a standing queue of ~1.7 s at
20 Mbit/s that every other tunnelled flow, interactive ones included, waits
behind. So each side manages its queue (on `serve` and `client`):

- **CoDel** (RFC 8289): once datagrams keep waiting longer than a target
  delay for a whole interval, the oldest are dropped at an increasing rate
  until the delay is back under the target. Bursts pass, and tunnelled TCP
  sees loss promptly and settles at a low queueing delay.
- **A hard limit**: datagrams that waited longer than this are always
  dropped. CoDel sheds traffic that does not slow down on loss (e.g.
  constant-rate UDP above the path's rate) too slowly; without the limit it
  would still queue up to the buffer size.

There is nothing to tune: the target, interval and limit (5, 100 and 200 ms)
follow the largest minimum RTT among the tunnel's paths once it exceeds
100 ms, e.g. 13.5, 270 and 540 ms on a 270 ms path. CoDel's interval must be
at least the RTT of the flows it drops for; in the netem testbed a fixed
100 ms interval on a 270 ms path made tunnelled TCP retransmit ~9x as much
(1434 vs 166 segments per 20 s download) at the same latency.

The stats endpoint counts drops per connection (`datagrams_dropped_delay`,
and `datagrams_dropped_overflow` for a full buffer).

### QUIC multipath

Both ends negotiate the QUIC multipath extension (up to 8 concurrent paths per
connection). The client attaches extra paths to its tunnel with `--path`
(repeatable):

```
rapidmasque client \
  --endpoint 'https://dns.example:4433/connect' --listen 127.0.0.1:5353 \
  --proxy-addr 203.0.113.7:4433 \
  --path '203.0.113.7:4433@192.168.1.20' \
  --path '[2001:db8::7]:4433' \
  --path '203.0.113.8:4433@10.64.0.5/backup'
```

A path spec is `REMOTE_IP:PORT[@LOCAL_IP][/backup][/priority=N][/rate=RATE][/rtable=N]`:

- `REMOTE_IP:PORT` - a proxy address. It may differ from the primary one (the
  proxy's IPv6 address, another address of the same host, ...); the server must
  answer on it, so bind the server to a wildcard address (`--addr [::]:4433` or
  `0.0.0.0:4433`) when it has several.
- `@LOCAL_IP` - the path's source address, e.g. the address of a second uplink
  (Wi-Fi + LTE, two ISPs). Omit it to let the OS route.
- `/backup` - a standby path: traffic is only scheduled on it when no
  non-backup path is usable.
- `/priority=N` - scheduling priority, 0-255, lower is preferred (default 0).
  See [Path priority](#path-priority). The primary path's priority is
  `--primary-priority` (default 0).
- `/rate=RATE` - send on the path at a fixed rate (bits per second, e.g.
  `48M`) instead of under congestion control, for a link of known, dedicated
  capacity. See [Fixed-rate paths](#fixed-rate-paths). The primary path's is
  `--primary-rate`.
- `/rtable=N` - OpenBSD only: send the path through routing table `N`
  (rtable(4)). See [Routing tables](#routing-tables-openbsd).

The primary path (`--proxy-addr`, or the resolved endpoint host) is the
handshake path, path 0 (path IDs are never reused: a re-opened path gets a new
one). If it gets no answer within 3 s, the client tries the handshake on the
extra paths' proxy addresses instead, in priority order (`/backup` paths
last; only paths without `@LOCAL_IP`, to another remote than the primary), so
the tunnel comes up even while the primary link is down; the primary path then
joins once it works.
Extra paths are opened once the tunnel is up. They, and the primary path, are
re-opened whenever they fail or are abandoned (quick retries backing off to
every 5 s), so a flapping uplink rejoins automatically. Every path has its own
1 s keepalive and is abandoned after 10 s of silence; the tunnel survives as
long as one path is alive. Path changes are logged on both ends.

How traffic spreads over paths depends on congestion control. noq tries the
usable non-backup paths in priority order (lowest `priority` first, then lowest
path ID) and sends on the first one that is not held back by its congestion
window or pacer:

- With BBRv3 (the default), traffic spills over to the next path when a path
  is held back, which **aggregates bandwidth** across paths. With equal
  priorities (the default) this spreads even light traffic over all paths.
- With `--congestion-control none`, nothing is ever held back, so all traffic
  takes the most preferred usable path and the other paths are hot standbys.
  Multipath then means **failover**: when that path dies, traffic moves to the
  next one once the dead path is abandoned (up to the 10 s path idle timeout).
  Use `/priority=N` and `/backup` to pick the preferred uplink.

#### Path priority

Give the paths different priorities to fill a preferred path first and spill
only the excess onto the others, e.g. a good 50 Mbit/s link A as the primary
path and a lossier 500 Mbit/s link B for overflow:

```
rapidmasque client ... \
  --proxy-addr 203.0.113.7:4433 \
  --path '203.0.113.7:4433@10.64.0.5/priority=1'
```

The priority applies in both directions: the client announces each path's
priority to the proxy (a rapidmasque extension frame on the HTTP/3 control
stream, which other HTTP/3 servers ignore), and the proxy schedules what it
sends the same way.

With BBRv3, a preferred path's pacer holds it back briefly after almost every
packet, so without more care traffic would spill onto B even at low load.
`--path-spill-threshold-ms` (on `serve` and `client`, default 10) sets how much
queueing delay is accepted on the preferred path first: while A can send
everything queued (tunnelled datagrams and stream data) within that time at
its current BBRv3 rate, B carries no data, only its keepalives. Once the queue
grows beyond that, or A's congestion window is full, the excess goes to B. A
larger threshold keeps more traffic on A at the cost of latency; `0` turns the
hold-back off. Each side's flag governs what it sends. Paths with equal
priority always share traffic, and `/backup` paths still only carry traffic
when no non-backup path is usable.

#### Fixed-rate paths

A link of known capacity that nothing else shares (a dedicated line) needs no
congestion control: `/rate=RATE` (or `--primary-rate` for the primary path)
sends on it at that fixed rate. Continuing the example above, with A a
dedicated 50 Mbit/s line:

```
rapidmasque client ... \
  --proxy-addr 203.0.113.7:4433 --primary-rate 48M \
  --path '198.51.100.9:4433/priority=1'
rapidmasque serve ... --max-path-rate 100M
```

- A then runs at a steady 48 Mbit/s: BBRv3 would keep probing above the line
  rate and periodically cut its window to re-measure the RTT, and each probe
  or cut moves traffic onto B. Set the rate a little below the line rate to
  leave room for IP/UDP headers.
- Spill-over to B starts exactly when more than the fixed rate is offered
  (the spill threshold applies as above), and stops when it is not.
- If A goes down, its window (about two round trips' worth at the fixed rate)
  fills within a round trip and traffic moves to B right away, as it would
  for a congestion-controlled path. Loss on A is not a congestion signal and
  never slows it down.
- The rate applies in both directions: the client announces it to the proxy,
  which applies it to what it sends on the path up to its `--max-path-rate`
  (requests above it are capped). Without `--max-path-rate` the proxy ignores
  such requests, since a fixed-rate path sends without congestion control.
- `/stats` shows each path's `fixed_rate_bps`.

#### In-order delivery

When traffic spills from a fast path onto a slower one (or a path with more
delay), datagrams of one flow arrive out of order. TCP inside the tunnel
(inside WireGuard, which passes reordering through) takes that as loss:
duplicate ACKs, spurious retransmissions and a lower sending rate. So by
default both ends deliver each flow's datagrams in order:

- The client asks for it on each flow (a `rapidmasque-sequence` request
  header) and a rapidmasque proxy agrees; both then number the datagrams they
  send (a rapidmasque HTTP datagram context, 4 bytes per datagram). Other
  MASQUE peers never agree, and the flow uses plain RFC 9298 datagrams.
- The receiver holds a datagram that arrives ahead of a gap until the gap
  fills, or for a hold time after which it gives up on the missing one and
  releases what it has, in order. The hold time follows how late datagrams
  that fill a gap actually arrive (plus a quarter, up to 250 ms), and decays
  while nothing arrives out of order; it starts at 10 ms.
- Datagrams that come in order are never held, so a flow on one path pays
  nothing beyond the 4 bytes; a genuinely lost datagram delays the ones after
  it by up to the hold time.
- `--in-order-delivery false` on the client turns it off for its flows.

#### Automatic path ranking

The client ranks paths by measured loss by default (`--path-ranking auto`;
`--path-ranking off` keeps the configured priorities as they are), for paths
whose quality varies (e.g. two cellular uplinks). Within each group of paths with the
same configured priority, a path whose loss is clearly worse than the group's
best is **demoted**: it falls behind the rest of its group (but never behind a
path with a worse configured priority), so traffic moves to the better paths.
It is **promoted** again once its loss recovers.

- Loss is sampled from what each end *sends*, so the client ranks the upload
  direction and asks the proxy (a rapidmasque extension frame on the HTTP/3
  control stream) to rank the download direction on its own measurements.
- A path is demoted when its loss is at least 5% and 3 points above the best
  path of its group, in 3 consecutive samples (a sample is ~40 packets, or the
  packets sent within 30 s on a quiet path), and in the smoothed loss rate.
  The best path of a group is never demoted, so paths that are all equally
  lossy keep sharing traffic. The 5% floor stays clear of the ~2% loss BBRv3
  causes itself while probing for bandwidth.
- A demoted path is PINGed every 100 ms (about 400 bytes/s) so its loss keeps
  being measured; it is promoted after 3 samples at no more than half those
  levels, typically within 15-30 s of the loss stopping. A path changes rank
  at most every 10 s.
- RTT is not used: smoothed RTT includes the queueing delay of whatever
  traffic a path carries, so ranking on it would chase traffic back and forth.
- With ranking on (the default), path priorities must be at most 127 (a
  demoted path's noq priority is `2 * priority + 1`); use
  `--path-ranking off` for higher ones.

Rank changes are logged on each end.

#### Routing tables (OpenBSD)

On OpenBSD each path can use its own routing table, e.g. to send it out a
second uplink whose default route lives in table 1:

```
route -T 1 add default 10.64.0.1
rapidmasque client ... --proxy-addr 203.0.113.7:4433 \
  --path '203.0.113.7:4433@10.64.0.5/rtable=1'
```

`--rtable N` sets the table of the primary path and of every path without its
own `/rtable` (by default, the process's table; see `route -T N exec`). The
client binds one extra UDP socket per routing table in use (`SO_RTABLE`) and
sends each path's packets through its table's socket; its replies come back to
that socket. noq's packets carry only their destination and source address,
so a path with `/rtable` needs a remote address, or a remote address plus
`@LOCAL_IP`, that no other path (including the primary) uses. An unprivileged
process may select any existing table while its own table is 0. Elsewhere,
`--rtable` and `/rtable=` are rejected at startup.

With extra paths configured, the client binds a dual-stack `[::]:0` socket so
IPv4 and IPv6 paths can share the connection (on systems without dual-stack
sockets, such as OpenBSD, a socket of the primary path's family instead). If the proxy does not negotiate
multipath (e.g. masque-go), extra paths are skipped with a warning and the
tunnel runs single-path.

### Stats endpoint

`--stats-listen IP:PORT` (on `serve` and `client`, off by default) serves a
JSON snapshot at `http://IP:PORT/stats`:

```
$ curl -s http://127.0.0.1:9100/stats
{
  "role": "client", "version": "0.1.0", "uptime_secs": 3600,
  "connections": [{
    "id": 140507909560848, "uptime_secs": 3590, "multipath": true,
    "path_ranking": true, "flows": 3,
    "info": { "endpoint": "proxy.example:4433", "proxy_addr": "203.0.113.7:4433", "ech": true },
    "sent_packets": 1043211, "lost_packets": 2210,
    "udp_tx": { "datagrams": 1040022, "bytes": 1380412218 }, "udp_rx": { ... },
    "paths": [{
      "id": 0, "remote": "203.0.113.7:4433", "local_ip": "192.168.1.20",
      "status": "available", "priority": 0, "base_priority": 0,
      "demoted": false, "ranked_loss": 0.001,
      "rtt_ms": 23.4, "cwnd": 412000, "mtu": 1452,
      "sent_packets": 900211, "lost_packets": 900, "sent_bytes": ..., "lost_bytes": ...,
      "congestion_events": 12, "udp_tx": { ... }, "udp_rx": { ... }
    }, ...]
  }]
}
```

Each live QUIC connection lists its multipath paths (open, or abandoned but
not yet discarded) with their effective noq `priority`, the configured
`base_priority`, the automatic ranking state (`demoted`, and `ranked_loss`, the
smoothed loss rate of what this end sends, once sampled) and noq's per-path
counters. On the server, `info` carries the client's handshake address, SNI
and ECH status. The endpoint is plain HTTP without authentication and
reveals peer addresses: bind it to loopback or a management network.

### Hot reload

Send `SIGHUP` to rebuild the TLS/ECH configuration *and* the rule table from
their files. New connections pick up rotated certificates; new requests pick up
the new rule table; existing connections keep
the configuration they handshook with. A failed reload (e.g. a half-written
file) is logged and the previous configuration is retained.

```
kill -SIGHUP "$(pidof rapidmasque)"
```

Hot reload uses tokio's signal handling and works on every Unix (Linux, macOS,
BSD).

### Encrypted Client Hello (ECH)

Generate a keypair + ECHConfig (prints the PEM bundle to stdout and the DNS
`ech=` value to stderr):

```
rapidmasque gen-ech-key --public-name public.example.com > ech.pem
```

Run the server with ECH termination:

```
rapidmasque serve ... --cert cert.pem --key key.pem --ech-key ech.pem
```

Offer ECH from the client with the published ECHConfigList:

```
rapidmasque client --endpoint ... --listen ... --ech-config "AEX+DQBB...AAA="
```

Certificate coverage with ECH is subtle. When ECH is **accepted**, the
handshake completes from the encrypted ClientHelloInner, so only the **inner**
(real) SNI is authenticated — the certificate must cover the real proxy hostname
the client puts in `:authority`, not the public name. The public name is the
cleartext cover identity; it only needs a valid certificate for the ECH
**rejection** fallback, where the client authenticates the outer name and retries
with the server's fresh `retry_configs`. A cert covering both names handles both
paths.

The server rejects ClientHellos whose SNI does not match any configured rule
authority host. With ECH accepted, this check is applied to the decrypted inner
SNI; rejected ECH fallbacks and ordinary non-ECH handshakes are checked against
the cleartext SNI.

Both ends log whether ECH was accepted on each connection (`ech=true`).

### Access control

By default the proxy performs **no client authentication**: any peer that can
reach it, complete TLS with a configured SNI host, and send a CONNECT-UDP request
matching a rule's authority + path is granted a tunnel. (The client still
authenticates the *server* via TLS unless `--insecure`.)

A secret can be embedded in a rule's endpoint **path** as a lightweight
shared-secret gate. The server matches on the path component (the query string is
ignored), so put the secret in a path segment — not the query:

```json
// rules.json
[{"endpoint": "https://proxy:4433/connect/s3cret-9f2c", "target": "192.0.2.10:53"}]
```

```
# client uses the same secret path:
rapidmasque client --endpoint 'https://proxy:4433/connect/s3cret-9f2c' --listen ...
```

A client requesting a different path (or none) is rejected with `404`. The path
is not exposed to passive on-path observers — it travels inside the encrypted
QUIC/HTTP3 stream (and ECH hides the SNI) — so this is enough to keep
opportunistic scanners from using an open proxy.

It is **not** real authentication, though:

- It is a single static bearer secret in a URL path: it can leak via logs, shell
  history, or config files, and a *failed* attempt is logged at debug level.
- There is no per-client identity, no selective revocation, and no rate-limiting
  by identity — rotating means updating the server and every client at once.
- It is replayable indefinitely by anyone who learns it, and the match is not
  constant-time.

For access control of untrusted clients, prefer a real scheme: `Proxy-Authorization`
validated at the request layer (proper `407`, per-client tokens, secret kept out
of the path/logs) or mTLS for cryptographic per-client identity. Neither is
implemented yet.

## Testing

Unit and in-process end-to-end tests: framing, QPACK/Huffman, endpoint
matching, ECH wire format, RFC 9001 packet-protection vectors, an in-memory
BoringSSL ECH handshake, and real noq connections on loopback (ECH accepted on
both peers, SNI-guard and certificate-verification failures, a second multipath
path carrying datagrams, and a full client -> server -> UDP target round trip
with ECH + multipath):

```
cargo test
```

End-to-end interop against masque-go (needs `go` and a masque-go checkout at
`../masque-go`, override with `MASQUE_GO=`):

```
./testing/interop.sh
```

The harness exercises: rapidmasque client -> masque-go proxy, masque-go
(variable-template) client -> rapidmasque pinned server, rapidmasque <->
rapidmasque, an ECH variant, SIGHUP certificate and rule reload checks, and a
multipath case (two extra paths via 127.0.0.2 / 127.0.0.3).

Behaviour on shaped links (Linux, root; needs `tc netem`, iperf3, `wg`,
ethtool and a `wireguard-go` binary):

```
sudo WIREGUARD_GO=/path/to/wireguard-go testing/netem/netem-bench.sh
```

It runs the production stack, TCP (iperf3) inside WireGuard (MTU 1280) inside
a rapidmasque tunnel, between two network namespaces whose link is shaped with
netem: 20 Mbit/s at 270 ms RTT with and without 1% loss, and 50 Mbit/s at
20 ms RTT. Each link is measured with the defaults (`auto`: BBRv3 with
RTT-scaled queue management) and with `--congestion-control none` (`REPEATS=n` reports medians over n runs),
reporting TCP goodput and
retransmits, the latency of a ping alongside the load, and the tunnel's drop
counters (`target/netem/report.md`). The `netem` CI workflow runs it on every
pull request and publishes the report in the job summary.

## Layout

- `src/server.rs` - the CONNECT-UDP proxy (rule-pinned): a task per connection
  and per flow.
- `src/client.rs` - the local UDP→CONNECT-UDP proxy client and multipath path
  maintenance.
- `src/ranking.rs` - per-connection path priorities and automatic path
  ranking by loss (`--path-ranking`, on by default).
- `src/routed_socket.rs` - the client's multi-socket noq socket for per-path
  OpenBSD routing tables (`/rtable=N`).
- `src/rules.rs` - the JSON endpoint→target rule table.
- `src/stats.rs` - the optional HTTP stats endpoint (`--stats-listen`).
- `src/quic.rs` - noq transport config (multipath, idle/keepalive) + BoringSSL
  context setup, ECH install hooks.
- `src/cc.rs` - congestion control choice: BBRv3 (default) or the no-op
  controller, and the fixed-rate controller of `/rate=RATE` paths.
- `src/reorder.rs` - in-order delivery of a flow's sequenced datagrams.
- `src/tls/` - BoringSSL as noq's TLS provider: the QUIC handshake session
  (`session.rs`) and packet/header protection with the multipath nonce
  (`keys.rs`).
- `src/h3.rs`, `src/qpack.rs` - minimal HTTP/3 (SETTINGS, Extended CONNECT)
  and static-table QPACK with Huffman decoding.
- `src/reload.rs` - SIGHUP cert/ECH/rule hot reload.
- `src/endpoint.rs`, `src/dgram.rs`, `src/varint.rs` - endpoint matching and
  HTTP/3 datagram / QUIC varint framing.
- `src/ech/` - ECH key material: wire format, PEM key files, keygen (shared
  with zeromasque).
- `testing/` - interop harness and Go helpers.

## Resilience

The client never exits: it redials the proxy indefinitely with capped
exponential backoff (100 ms → 5 s), so a server restart, a dropped NAT mapping,
or any transient failure recovers automatically. The local listen socket stays
bound across reconnects, and flows reopen lazily as local datagrams arrive (apps
retransmit lost UDP and self-heal). With extra paths, a dial whose primary
path does not answer within 3 s falls back to the extra paths' proxy
addresses. A 1 s keepalive (ack-eliciting) on every
path keeps idle NAT mappings warm and makes a dead path detectable within the
10 s idle timeout; with multipath, losing one path does not drop the tunnel.

The server reaps connections that idle out and closes their target sockets, so
vanished clients don't leak resources.

## Performance & tuning (high-RTT links)

The whole tunnel is a single QUIC connection and every UDP payload rides an
*unreliable* QUIC DATAGRAM (RFC 9297/9298) — there is no tunnel-level
retransmission, by design. The consequence: any packet the kernel drops because
a UDP socket buffer overflowed becomes a loss the *tunnelled* protocol must
recover from. Over a high-RTT path even a few percent loss collapses an inner
TCP flow (Mathis: throughput ≈ MSS / (RTT·√loss)), so a tunnel that drops 40 %
of a burst can crush a 20 Mbit/s TCP transfer down to a few hundred Kbit/s.

rapidmasque therefore requests large send/receive buffers (8 MB) on every UDP
socket. **The kernel silently clamps that request to `net.core.rmem_max` /
`net.core.wmem_max`, which default to ~208 KB on stock Linux** — far below the
bandwidth-delay product of a fast, high-latency link (e.g. 20 Mbit/s × 270 ms ≈
675 KB). On both the proxy host and the client host, raise those ceilings:

```sh
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
# persist in /etc/sysctl.d/99-rapidmasque.conf:
#   net.core.rmem_max = 16777216
#   net.core.wmem_max = 16777216
```

Measured over an emulated 270 ms RTT path, this takes a 2000 pkt/s
(~19 Mbit/s) flow from ~40–60 % loss (erratic) to a stable ~3 %. Also keep the
tunnelled interface's MTU low enough that an inner packet plus encapsulation
fits one QUIC DATAGRAM (these cannot fragment). By default, QUIC packets start at exactly
1356 bytes of UDP payload, which leaves the 1318 bytes of datagram room that a
1280-MTU inner tunnel such as WireGuard needs from the first packet; DPLPMTUD
can raise this to 1452 bytes, but it never drops below 1356 (black-hole
detection does not shrink it). The client<->proxy path must therefore carry
1384-byte IPv4 (1404-byte IPv6) packets; on a path that cannot, full-size
packets are lost rather than the tunnel quietly narrowing below what a
1280-MTU inner tunnel needs, sequence number included (see in-order
delivery below). (The 1318 bytes assume the 8-byte connection IDs
rapidmasque peers use; against a server issuing longer CIDs there is less
room.)

Use `--min-mtu BYTES` on `serve` and/or `client` to override the initial and
minimum QUIC packet size for what that side sends (default 1356, minimum
1200). The value counts UDP payload bytes, excluding IP and UDP headers.
For example, `--min-mtu 1200` supports smaller outer paths, but may require
a smaller tunnelled interface MTU until discovery finds more room. Discovery
can raise the packet size; black-hole detection never lowers it below the
configured minimum.

BBRv3 (the default) paces and models the bottleneck. With
`--congestion-control none`, bursts go out unpaced as fast as the socket accepts
them; drops anywhere on the path surface as loss to the tunnelled protocol,
which reacts as it would on a raw link, and the socket-buffer sizing above is
what keeps those bursts from being dropped locally.

## Notes & limitations

- Only context ID 0 (raw UDP payloads) is proxied; other HTTP-datagram contexts
  and stream capsules are discarded, matching masque-go.
- The server does not perform QUIC Retry / stateless address validation; it is
  intended for trusted deployments and interop testing, not open-internet
  hardening.
- QUIC v1 only; no 0-RTT or session resumption (the server sends no tickets).
- Extra multipath paths are client-initiated, and the primary path cannot be
  pinned to a local address.
- The client opens one CONNECT-UDP flow per local source address (bounded by the
  connection's stream limit) and keeps flows for the connection's lifetime; the
  first datagram of a new flow waits one round-trip for the `200` response.
- No client authentication by default; see [Access control](#access-control) for
  the path-secret gate and its limits.
- Unlike zeroserve, the proxy does not (yet) apply namespace/landlock sandboxing.
- Transparent forwarding and `fwmark` are Linux-only; everything else also runs
  on macOS/BSD.
