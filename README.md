# Aether

A from-scratch post-quantum peer-to-peer operating system in `no_std` Rust — an early prototype.

<p>
  <a href="https://github.com/Sifr-Dev/Aether/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Sifr-Dev/Aether/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Rust stable" src="https://img.shields.io/badge/RUST-STABLE-dea584?logo=rust&logoColor=white">
  <img alt="Tests: 64 passing" src="https://img.shields.io/badge/TESTS-64_PASSING-39c5cf">
  <img alt="License: MIT" src="https://img.shields.io/badge/LICENSE-MIT-2ea043">
</p>

> Crate names remain `verrev-*`; the GitHub repository and product name are
> Aether (`https://github.com/Sifr-Dev/Aether`).

## What it is

Aether is a vertically integrated P2P system: post-quantum cryptography
(ML-KEM-1024, ML-DSA-87), capability security, content-addressed storage, CRDTs
and a UDP transport, all written without external crates. Every library is
`#![no_std]` with `extern crate alloc`; the same crates build on Linux today, and
a dedicated microkernel target is the long-term direction.

This is a prototype in an early phase, not a working distributed OS. The UDP
handshake, hashes, AEAD, capability checks, Merkle tree and erasure coding are
implemented and tested. DHT routing RPCs, mesh route discovery, distributed
storage, WASM execution, the UI and all applications are incomplete or stubs.

## Current capabilities

- **SHA-3 / SHAKE** — Keccak-f[1600] with SHA3-256/512 and SHAKE128/256;
  round constants and rho offsets generated from formulas. `libs/verrev-hash/src/sha3.rs`;
  5 tests including NIST empty-string vectors (`cargo test --workspace`).
- **ML-KEM-1024** — full NTT, CPAPKE and CCAKEM in
  `libs/verrev-crypto/src/kyber.rs`; 3 unit tests plus 4 official NIST ACVP
  keygen/encaps/decaps vectors:
  `cargo test -p verrev-crypto --features test-vectors`.
- **ML-DSA-87** — full NTT and key generation in
  `libs/verrev-crypto/src/dilithium.rs`; key generation matches FIPS 204 and
  passes its official vector. Sign/verify round-trip internally but are **not
  yet FIPS 204 conformant**; the 3 official sign/verify checks are `#[ignore]`d
  with the divergence recorded rather than weakened.
- **AEAD** — XChaCha20-Poly1305 and AES-256-GCM with RFC 8439, NIST GCM and
  independent OpenSSL-derived vectors; 12 tests in
  `libs/verrev-crypto/src/aead.rs`.
- **Identity and capabilities** — identity = SHA3-256(ML-DSA public key)
  (`libs/verrev-identity`); capability rights, delegation and revocation with
  tested non-escalation (`libs/verrev-capability`, 4 tests).
- **Content-addressed store** — `libs/verrev-store/src/lib.rs`; `get` verifies
  the hash and declared size before returning data, with 5 tests covering
  missing, truncated and corrupted blocks.
- **UDP transport handshake** — `libs/verrev-transport`; a real two-party
  Kyber + Dilithium handshake over loopback UDP reaches `Established`
  (`test_endpoint_handshake_over_udp`), with packet framing and an
  XChaCha20-Poly1305 encrypted channel.
- **DHT routing table** — `libs/verrev-p2p/src/dht.rs`; 256 buckets, XOR
  distance, `find_closest`; 6 tests. Peer discovery RPCs are not implemented.
- **Onion packet build/peel** — `libs/verrev-mesh/src/onion.rs`; one real test.
  Route discovery, circuit key exchange and multi-hop forwarding are not.
- **CRDT text and Merkle trees** — `libs/verrev-sync`; text insert/delete
  (1 test) and Merkle root/diff over dynamic leaves (9 tests).
- **Erasure coding** — `libs/verrev-diststore/src/erasure.rs`; encode/decode
  round-trip test. The distributed store itself returns explicit errors, and
  no peer placement exists.
- **Local database** — `libs/verrev-db`; BTreeMap-backed KV, queue and document
  stores.
- **Deterministic build** — release profile uses fat LTO, one codegen unit and
  `panic = "abort"`; all crypto tables are generated from formulas.

## Quick start

```sh
git clone https://github.com/Sifr-Dev/Aether.git
cd verrev
cargo build --workspace --locked
cargo test --workspace --locked -- --test-threads=1
```

Requirements: stable Rust (Edition 2024; CI uses `stable`). The tests are run
single-threaded because several crypto tests are intentionally state-sensitive.

Official conformance fixtures are behind a feature so published builds cannot
call the internal FIPS entry points:

```sh
cargo test -p verrev-crypto --locked --features test-vectors -- --test-threads=1
```

## Verification

Run on this host (Ryzen 7 7435HS, Linux, Rust 1.100.0):

```sh
cargo build --workspace --locked
cargo test --workspace --locked -- --test-threads=1
cargo test -p verrev-crypto --locked --features test-vectors -- --test-threads=1
```

Observed:

- `cargo build --workspace --locked` exits 0 (4 manifest warnings about unused
  workspace dependencies; no errors).
- `cargo test --workspace --locked` → **64 passed, 0 failed, 0 ignored**:
  crypto 27, sync 10, p2p 6, hash 5, store 5, capability 4, runtime 4,
  diststore 1, mesh 1, transport 1.
- `cargo test -p verrev-crypto --features test-vectors` → 27 unit + 2 ML-DSA
  checks (1 official key-generation vector and 1 internal round-trip) + 4
  ML-KEM vectors passed, **3 ML-DSA sign/verify checks ignored** for the
  recorded non-conformance.

No benchmark suite exists, so no performance claims are made.

## Architecture

```
libs/verrev-syscall   raw Linux syscall shim (getrandom, sockets, mmap)
libs/verrev-hash      SHA-3 / SHAKE
libs/verrev-crypto    ML-KEM-1024, ML-DSA-87, XChaCha20-Poly1305, AES-256-GCM
libs/verrev-identity  identity and signing
libs/verrev-capability rights, delegation, revocation
libs/verrev-store     content-addressed block store
libs/verrev-fs        directory map
libs/verrev-transport UDP endpoint, handshake, packets, encrypted channel
libs/verrev-relay     store-and-forward relay
libs/verrev-p2p       DHT routing table and node
libs/verrev-mesh      onion packets, routing table, circuit types
libs/verrev-name      in-memory name records
libs/verrev-sync      text CRDT, Merkle tree, sync protocol
libs/verrev-diststore erasure coding and distributed-store interface
libs/verrev-runtime   WASM module parsing (execution unsupported)
libs/verrev-compute   jobs, credit ledger, scheduler interface
libs/verrev-db        KV, queue and document stores
libs/verrev-ui        scene/widget types and compositor interface
libs/verrev-net       network simulation for tests
apps/                 nine application crates, currently stubs
```

The dependency chain is strictly bottom-up; no circular dependencies.

## Design decisions

- **Post-quantum only:** ML-KEM-1024 for KEM, ML-DSA-87 for signatures. No RSA,
  ECDSA, X25519 or hybrid fallback.
- **SHA-3 at layer 0:** content and identities are addressed by hash.
- **No external crates:** everything is owned code, `no_std` + `alloc`.
- **Constant-time comparisons:** security comparisons use `util::ct_eq`.
- **Deterministic release builds:** fat LTO, one codegen unit, abort on panic.

## Limitations

- **ML-DSA sign/verify do not yet conform to FIPS 204.** Internal round-trips
  pass; the official sigGen/sigVer vectors are ignored, and importing an official
  signature does not verify. Do not use this for signature security claims.
- **No real mesh:** DHT lookup over the network, route discovery, NAT traversal,
  multi-hop circuits and onion route keys are stubs. `route_message` uses a
  single hop with a zero key.
- **Transport is local-only in evidence:** the handshake test runs over loopback
  UDP. No internet, NAT or lossy-network validation exists.
- **No persistence:** the content store and database are in memory; the store's
  `put`/`get` are verified but do not survive process exit.
- **Distributed storage is not implemented:** `put`, `get` and `repair` return
  explicit errors; only erasure encode/decode is real.
- **No WASM execution:** the runtime parses a module header and returns
  `UnsupportedExecution` for compile/instantiate/call.
- **No UI and no applications:** the compositor, font and text layout are stubs;
  all nine `apps/` binaries print a placeholder line.
- **Relay:** store-and-forward works in memory; duplicate detection, TTL
  enforcement and persistence are absent.

## Roadmap (NOT IMPLEMENTED)

- FIPS 204 conformant ML-DSA-87 signing and verification, with the official
  vectors enabled.
- Network DHT RPCs, bucket refresh and peer discovery.
- Mesh route discovery, circuit key exchange and multi-hop onion forwarding.
- Persistent content storage and a working distributed store with repair.
- A WASM runtime with real execution.
- UI compositor and the application crates.
- End-to-end encrypted messaging across the mesh.

## License

MIT — see `LICENSE`.
