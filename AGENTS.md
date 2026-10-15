# Repository Guidelines

rapidmasque is a port of [zeromasque](https://github.com/losfair/zeromasque) to
tokio + noq with QUIC multipath. Keep it functionally aligned with zeromasque
(CLI, rule table, ECH key format, behavior) unless a difference is deliberate
and documented in `README.md`.

## Project Structure & Module Organization

- `src/` contains the proxy server, client, the noq transport config
  (`quic.rs`), outer congestion-control selection (`cc.rs`), the SIGHUP reload
  task, the JSON endpoint→target rule table (`rules.rs`), and the HTTP/3
  datagram + endpoint matching.
- `src/tls/` is BoringSSL as noq's TLS provider: `session.rs` drives
  BoringSSL's QUIC handshake API (`SSL_set_quic_method`) behind
  `noq::crypto::Session`; `keys.rs` does packet/header protection, initial
  keys, key updates and Retry tags on BoringSSL primitives.
- `src/h3.rs` + `src/qpack.rs` are a minimal HTTP/3 (control stream SETTINGS,
  Extended CONNECT) with static-table-only QPACK. `src/qpack_tables.rs` is
  generated data (Huffman codes + static table); do not hand-edit it.
- `src/ech/` holds ECH key material (wire format, PEM key files, keygen),
  shared with zeromasque.
- `testing/` contains the masque-go interop harness and its Go helpers.

## Build, Test, and Development Commands

- `cargo build` — compile the `rapidmasque` binary (subcommands: `serve`,
  `client`, `gen-ech-key`). BoringSSL builds from source: needs `cmake` + Go.
- `cargo test` — unit tests plus in-process noq end-to-end tests (`e2e_test.rs`:
  ECH accepted on both peers, SNI guard, cert verification, multipath, full
  tunnel). They bind loopback UDP and use 127.0.0.2 as a second source address
  (Linux routes all of 127.0.0.0/8 to `lo`).
- `./testing/interop.sh` — end-to-end interop against masque-go (needs `go` and a
  masque-go checkout at `../masque-go`, override with `MASQUE_GO=`).
- `testing/netem/netem-bench.sh` — tc netem testbed (root): TCP inside
  wireguard-go inside the tunnel across two network namespaces with shaped
  links; writes a Markdown report. CI runs it as the `netem` workflow
  (report only). `ALLOW_TBF=1` shapes rate-only with tbf where the kernel lacks
  netem (development only).
- `kill -SIGHUP <pid>` — hot-reload the server's TLS certificate, ECH keys and
  rule table (any Unix).

## Design Constraints

- TLS must stay on BoringSSL: rustls cannot terminate ECH. noq is used with
  `default-features = false` (no rustls); its `ring` feature only backs the
  stateless-reset HMAC / token key.
- BoringSSL installs the server's 1-RTT *read* secret only after the client
  Finished, but noq needs both 1-RTT directions when the server flight is
  written. `tls::session::capture_client_app_secret` (a keylog hook on the
  server context) supplies it — keep `ServerTls::new` installing it.
- The multipath AEAD nonce folds the path ID into the IV
  (`keys::PacketKey::nonce`); noq keeps `PathId::as_u32` private, so the value
  is recovered via `noq_proto::coding::Encodable`. `noq-proto` must stay the
  same version noq uses.
- `boring = "4"` keeps the ECH code identical to zeromasque; boring 4's `PKey`
  has no X25519 `generate`, so ECH HPKE keypairs are minted via `boring-sys`.
- Congestion control defaults to BBRv3; `--congestion-control none`
  (`cc::NoCongestionControl`) is opt-in for already congestion-controlled
  payloads (TCP inside WireGuard), to avoid double CC. noq checks the window
  per packet, so there is no per-frame (datagram-only) exemption, and noq is
  not patched for one. With `none`, noq's path scheduler keeps all traffic on
  the most preferred usable path (multipath = failover); BBRv3 spills over
  across paths (aggregation).
- noq (and noq-proto) come from the losfair/noq fork, pinned by git commit, for
  per-path scheduling priority (`Path::set_priority`, lower is preferred) and
  `TransportConfig::path_spill_threshold`. Priorities are local to each end:
  the client sets them from `--path .../priority=N` / `--primary-priority` and
  announces them to the server with the `FRAME_PATH_PRIORITY` extension frame
  on its HTTP/3 control stream (`src/h3.rs`); the server applies them to its
  side of each path. Keep both noq crates on the same commit.
- `src/ranking.rs` owns each connection's path priorities (`PathPriorities`:
  configured base priority + demoted flag, effective noq priority
  `2 * base + demoted` with ranking on, `base` otherwise) and the
  `--path-ranking auto` ranker (the client default): a pure `Ranker` state machine (unit-tested
  with synthetic counters) driven by a task that samples `Path::stats()` loss
  (excluding PLPMTUD probes) per path and PINGs demoted paths. The client
  enables it on the server with the `FRAME_PATH_RANKING` control frame. noq
  has no path list API: path IDs are sequential and never reused, so the
  ranker scans IDs above the highest seen. Do not rank on smoothed RTT (it
  tracks the path's own queueing and flaps).
- `src/routed_socket.rs` implements per-path OpenBSD routing tables
  (`--path .../rtable=N`, `--rtable`): noq runs all paths over one
  `AsyncUdpSocket`, so `RoutedUdpSocket` wraps the default socket plus one
  socket per routing table (`SO_RTABLE`, set before bind) and routes each
  `Transmit` by destination + source IP (canonicalised; noq uses IPv4-mapped
  addresses on dual-stack sockets). It is tested on Linux with a second
  default-table socket (`Route::rtable: None`); the OpenBSD smoke test
  (`.github/scripts/smoke-test.sh`) exercises a real `rtable=0` path. OpenBSD
  has no dual-stack sockets: `quic::client_bind_socket` falls back to the
  primary's family there.
- Outgoing datagram queue management (always on, no flags; `quic::DATAGRAM_CODEL`)
  is noq's `TransportConfig::datagram_send_codel` (CoDel plus a hard
  `max_delay`, in the losfair/noq fork): the queue that builds up is noq's
  send buffer, so drops must happen there, where the queueing time is known.
  Shared transport flags live in `cli::TransportArgs` (flattened into `serve`
  and `client`), which builds `quic::TransportOptions`.
- `src/stats.rs` is the optional `--stats-listen` endpoint: a minimal
  hand-written HTTP/1.1 responder (no HTTP crate) serving `GET /stats` JSON
  from a `Registry` of live connections (server and client register each
  connection with its `PathPriorities`). Path lists come from
  `quic::PathScan`, refreshed every second per registered connection.

## Release Builds

- Linux musl: native static build in Alpine with Alpine's Rust
  (`.github/scripts/build-musl.sh`); rustup's musl toolchain links build
  scripts statically and breaks bindgen.
- OpenBSD: cross-built from Linux (`.github/scripts/cross-openbsd.sh`), then
  run in OpenBSD VMs (`smoke-test.sh`; only amd64 gates releases, the emulated
  arm64 VM is too slow). Gotchas it encodes: tier-3 target
  (nightly `-Zbuild-std`, pinned in CI); unversioned `.so` symlinks in the
  sysroot; `-z nobtcfi` via rust-lld; clang >= 22 (older LLVM crashes on
  aarch64-openbsd stack-protector code); a forced `<pthread.h>` include for
  boring-sys 4's BoringSSL (the native OpenBSD build fails the same way).
- `src/openbsd_arm64.rs` supplies BoringSSL's missing `OPENSSL_cpuid_setup`
  for OpenBSD/aarch64 (reads `machdep.id_aa64isar0`).

## Coding Style & Naming Conventions

- Follow standard Rust style; `snake_case` for functions/vars, `CamelCase` for
  types. Run `cargo fmt` before submitting, and keep
  `cargo clippy --all-targets -- -D warnings` clean.
- Keep modules small and focused; keep CLI flags documented in `src/cli.rs`.
- Keep `README.md` in sync with user-facing behavior and CLI changes.

## Testing Guidelines

- `ech_test.rs` checks the ECH helpers on an in-memory BoringSSL handshake;
  `e2e_test.rs` checks ECH acceptance on real noq connections via
  `tls::HandshakeData::ech_accepted`.
- `tls::keys` tests pin the RFC 9001 appendix vectors; any change to packet
  protection must keep them passing.
- The interop harness must keep passing in both directions against masque-go.

## Security & Configuration Tips

- TLS expects PEM files; use local test certs (see `testing/gencert.go`).
- With ECH accepted, only the inner (real) SNI is authenticated, so the
  certificate must cover the real proxy hostname clients send in `:authority`.
  The public name only needs a valid certificate for the ECH-rejection fallback.
