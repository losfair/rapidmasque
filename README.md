# rapidmasque

A **multipath MASQUE / CONNECT-UDP** proxy and client written in Rust, built on
[`tokio`](https://tokio.rs), [`noq`](https://github.com/n0-computer/noq) (QUIC;
n0's quinn fork with multipath and BBRv3) and
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
| Multipath | no | yes (`client --path`) |
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

A path spec is `REMOTE_IP:PORT[@LOCAL_IP][/backup]`:

- `REMOTE_IP:PORT` - a proxy address. It may differ from the primary one (the
  proxy's IPv6 address, another address of the same host, ...); the server must
  answer on it, so bind the server to a wildcard address (`--addr [::]:4433` or
  `0.0.0.0:4433`) when it has several.
- `@LOCAL_IP` - the path's source address, e.g. the address of a second uplink
  (Wi-Fi + LTE, two ISPs). Omit it to let the OS route.
- `/backup` - a standby path: traffic is only scheduled on it when no
  non-backup path is usable.

The primary path (`--proxy-addr`, or the resolved endpoint host) is path 0.
Extra paths are opened once the tunnel is up. They, and the primary path, are
re-opened whenever they fail or are abandoned (quick retries backing off to
every 5 s), so a flapping uplink rejoins automatically. Every path has its own
1 s keepalive and is abandoned after 10 s of silence; the tunnel survives as
long as one path is alive. Path changes are logged on both ends.

How traffic spreads over paths depends on congestion control. noq sends on the
lowest-numbered usable non-backup path that has congestion-window room:

- With BBRv3 (the default), traffic spills over to the next path when a
  path's window is full, which **aggregates bandwidth** across paths.
- With `--congestion-control none`, no window ever fills, so all traffic takes
  the lowest-numbered usable path and the other paths are hot standbys.
  Multipath then means **failover**: when that path dies, traffic moves to the
  next one once the dead path is abandoned (up to the 10 s path idle timeout).
  Use path order and `/backup` to pick the preferred uplink.

With extra paths configured, the client binds a dual-stack `[::]:0` socket so
IPv4 and IPv6 paths can share the connection. If the proxy does not negotiate
multipath (e.g. masque-go), extra paths are skipped with a warning and the
tunnel runs single-path.

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

## Layout

- `src/server.rs` - the CONNECT-UDP proxy (rule-pinned): a task per connection
  and per flow.
- `src/client.rs` - the local UDP→CONNECT-UDP proxy client and multipath path
  maintenance.
- `src/rules.rs` - the JSON endpoint→target rule table.
- `src/quic.rs` - noq transport config (multipath, idle/keepalive) + BoringSSL
  context setup, ECH install hooks.
- `src/cc.rs` - congestion control choice: BBRv3 (default) or the no-op
  controller.
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
retransmit lost UDP and self-heal). A 1 s keepalive (ack-eliciting) on every
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
fits one QUIC DATAGRAM (these cannot fragment). QUIC packets start at 1400 bytes
of UDP payload (~1362 bytes of datagram room), enough for a 1280-MTU inner
tunnel such as WireGuard (1314-byte datagrams) from the first packet; DPLPMTUD
can raise this to 1452 bytes, but it never drops below 1400 (black-hole
detection does not shrink it). The client<->proxy path must therefore carry
~1450-byte IP packets; on a path that cannot, full-size packets are lost rather
than the tunnel quietly narrowing below what a 1280-MTU inner tunnel needs.

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
