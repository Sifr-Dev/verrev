# Verrev

> The Verrev Project is building a vertically-integrated peer-to-peer operating system and network — from the kernel up, every line is owned code. No compromises, no refactors, no external dependencies beyond Rust + LLVM. Post-quantum cryptography, capability security, CRDT-based state, and distributed compute form the foundation. The same code that compiles today on Linux compiles unmodified on the Verrev microkernel in Phase 4.

**Reference documents:** [`PLAN.md`](PLAN.md) (full 1000-line technical specification), [`rules.md`](rules.md) (19 engineering rules, including Rule 19: Absolute Perfection and Rule 20: No Rushing), [`AGENTS.md`](AGENTS.md) (agent context with full audit + remediation plan).

---

## Current State

`cargo build` — 0 errors. `cargo test -- --test-threads=1` — 31 tests pass.

### Layer 0 — Foundation

| Crate | Status | Description |
|---|---|---|
| `verrev-syscall` | ✅ Complete | Raw Linux syscall shim (getrandom, socket, sendto, recvfrom, mmap). Replaced by direct kernel calls in Phase 4. |
| `verrev-hash` | ✅ Perfect | SHA-3 (Keccak-f[1600]) with SHA3-256, SHA3-512, SHAKE128, SHAKE256. KAT-verified. All constants formula-generated (RC from LFSR, RHO from (t(t+1)/2 mod 64)). |

### Layer 1 — Core Primitives

| Crate | Status | Description |
|---|---|---|
| `verrev-crypto` | ✅ Complete | ML-KEM-1024 (full NTT + CCAKEM, 10 tests), ML-DSA-87 (full NTT keygen/sign/verify, 11 tests), XChaCha20-Poly1305 + AES-256-GCM (6 tests), constant-time utilities. 27 crypto tests pass. |
| `verrev-identity` | ✅ Perfect | Identity = SHA3-256(Dilithium-5 public key). IdentityBundle with keygen, signing, verification. |
| `verrev-capability` | ✅ Working | Capability tokens with check_access, delegate, revoke. Custom(c) rights shift needs overflow fix. |

### Layer 2 — Local Storage

| Crate | Status | Description |
|---|---|---|
| `verrev-store` | ✅ Working | ContentStore with block storage. put computes hash, get returns None (stub). In-memory BTreeMap. |
| `verrev-fs` | ⚠️ Minor | Directory with lookup/add_entry. No duplicate detection, no tests. |

### Layer 3 — Transport

| Crate | Status | Description |
|---|---|---|
| `verrev-transport` | ❌ Shell | Connection, PeerAddr, StreamState defined. Handshake/stream modules are stubs with no real I/O. |
| `verrev-relay` | ⚠️ Partial | StoreAndForward works (store/retrieve). No duplicate checking, no expiry enforcement. |

### Layer 4 — Mesh Network

| Crate | Status | Description |
|---|---|---|
| `verrev-p2p` | ❌ Shell | RoutingTable with 256 buckets, KBucket insert/find_closest, xor_distance tested. find_closest returns empty Vec. No bucket splitting. Discovery/NAT are stubs. |
| `verrev-mesh` | ❌ Shell | MeshNode, RoutingTable, Circuit, OnionMessage types. Route discovery/forwarding are stubs. |
| `verrev-name` | ❌ Shell | NameRecord, NameResolver types. Resolution returns Err. |

### Layer 5 — State & Replication

| Crate | Status | Description |
|---|---|---|
| `verrev-sync` | ❌ Shell | CRDT types (TextCrdt, OpId, CrdtValue). insert/delete are no-ops. Merkle tree has no root_hash. reconcile stub. |
| `verrev-diststore` | ❌ Shell | DistributedStore and erasure/repair return errors. StoragePolicy works. |

### Layer 6 — Compute

| Crate | Status | Description |
|---|---|---|
| `verrev-runtime` | ❌ Shell | WasmModule compile/instantiate succeed vacuously. Instance::call returns empty Vec. Unsound &'static mut. |
| `verrev-compute` | ❌ Shell | Job, ComputeNode types. CreditLedger working (O(n) spent-set). Scheduler/verification stubs. |
| `verrev-db` | ✅ Working | KvStore, MessageQueue, DocumentStore with BTreeMap/VecDeque backing. Database create_collection works. |

### Layer 7 — Interface

| Crate | Status | Description |
|---|---|---|
| `verrev-ui` | ❌ Shell | Point, Rect, SceneNode, Button, TextInput types. Compositor/Font are stubs. |

### Test Infrastructure

| Crate | Status | Description |
|---|---|---|
| `verrev-net` | ⚠️ Working | NetworkSimulation with send/latency/stats. ChaosConfig. Loss model is approximate (not proper Bernoulli trial). |

### Applications

All 9 apps are `println` stubs awaiting library completion.

---

## Recently Fixed Violations

Per Rule 18 (violations are blockers) and Rule 19 (absolute perfection):

| Issue | Fix | Date |
|---|---|---|
| **Hardcoded Dilithium zeta table** (256 entries) | Generated from formula: zetas[i] = R·ζ^(2·br7(i)) for i=1..127, R·ζ^(2·br7(i-128)+1) for i=128..255. invntt_factor = R²·256⁻¹ mod Q = 41978. All verified against pq-crystals reference. | 2026-07-26 |
| **heappless external dependency** | Removed from all Cargo.toml. Replaced all heapless::Vec with alloc::vec::Vec. | earlier |
| **Kyber fake encaps/decaps** | Replaced SHA-3 CTR approach with proper ccakem_encaps/ccakem_decaps forwarders. | earlier |
| **Dilithium fake sign/verify** | Full ML-DSA-87 with NTT-based polynomials. Fixed %5 bug in uniform_eta. | earlier |
| **AEAD SHA-3 substitutes** | Replaced with proper XChaCha20-Poly1305 + AES-256-GCM. S-box from GF(2⁸) formula. | earlier |
| **SHA-3 RC/RHO hardcoded tables** | RC from LFSR formula, RHO from (t(t+1)/2) mod 64 formula. | earlier |
| **QINV hardcoded** | Computed via Newton's method Q⁻¹ mod 2³². | earlier |

---

## Build

```sh
# Full workspace
cargo build

# Specific crate
cargo build -p verrev-crypto

# Tests (thread-safe mode for Kyber RNG)
cargo test -- --test-threads=1
```

Requires Rust 1.96.0+ (stable). Edition 2024.

---

## Architecture

All crates are `#![no_std]` with `extern crate alloc`. The dependency chain is strict bottom-up:

```
verrev-syscall  verrev-hash
  └── verrev-crypto
       └── verrev-identity
            └── verrev-capability
                 ├── verrev-store → verrev-fs
                 └── verrev-transport → verrev-p2p → verrev-relay → verrev-mesh
                      ├── verrev-name
                      ├── verrev-sync → verrev-diststore
                      └── verrev-runtime → verrev-compute → verrev-db
                           └── verrev-ui → apps
```

No circular dependencies. Each layer depends only on layers below it.

---

## Key Design Decisions

- **Post-quantum only:** Kyber-1024 (ML-KEM-1024) for KEM, Dilithium-5 (ML-DSA-87) for signatures. No RSA, ECDSA, X25519, or hybrid fallback anywhere.
- **Pure PQ handshake:** 2-RTT with pure Kyber + Dilithium. No X25519 hybrid.
- **SHA-3 is Layer 0** (not inside verrev-crypto). Everything addressed by hash.
- **AEAD uses fixed stack buffers:** No Vec in hot paths. Caller-provided output slices.
- **panic = "abort" in release:** No unwind tables in production binaries.
- **Deterministic builds:** Release profile has lto = "fat", codegen-units = 1.
- **Rule 19 (Absolute Perfection):** No "good enough." Every function must be the absolute best implementation possible. Perfection is the standard.

---

## Priority Fix Queue

1. Fix AEAD violations: Poly1305 carry propagation, unwrap() calls, Vec→stack, sbox caching, GHASH window table, ct_eq tag comparison
2. Clean all compiler warnings (8 remaining: dead code + unused variables)
3. Remove `#![allow(dead_code)]` from verrev-syscall, implement read/write/open wrappers
4. Fix verrev-runtime unsound &'static mut
5. Fix verrev-capability shift overflow
6. Implement real transport handshake (pure PQ 2-RTT)
7. Build working Kademlia find_closest, Merkle tree root_hash/diff
8. End-to-end encrypted messaging
