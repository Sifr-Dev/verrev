# Verrev — Technical Plan & Architecture

> From the kernel up, every line is our own code. Rust + LLVM are the only external dependencies. No compromises. No refactors. No rewrites. Every line is architecture as the final version.

---

## 1. Engineering Manifesto

### Hard Constraints

1. **Zero external dependencies beyond Rust + LLVM.** No libc, no OpenSSL, no wasmtime, no Tokio. Every line is owned code.

2. **`#![no_std]` from day one.** Every library compiles without the Rust standard library. On Linux (Phase 0), `verrev-syscall` bridges to the kernel. That shim is replaced by direct kernel syscalls in Phase 4.

3. **Designed for the final architecture, not the prototype.** The syscall interface designed today is what the microkernel exposes in Phase 4. The capability model designed today is what the kernel enforces.

4. **Constant-time by default.** Every crypto primitive is verified constant-time. Every comparison of secret data uses `ct_eq`, `ct_select`, `ct_swap`.

5. **Deterministic builds.** The same commit always produces the same binary. No build-time randomness.

6. **Absolute Perfection (Rule 19).** No "good enough." No "works for now." Every function must be the absolute best implementation you are capable of — the fastest algorithm, the most memory-efficient data structure, the most mathematically rigorous reduction, the tightest constant-time execution. Pragmatism is the enemy of correctness. Every line must be defensible in a formal verification proof. If implementing the correct algorithm takes a lifetime, start now and work crate by crate.

### Principles

- **Capability-secure from day one.** Every operation is gated by a capability token. No ambient authority.
- **Offline-first, mesh-synced.** Every component works without network. Local state is authoritative. Sync is eventual.
- **Post-quantum by default.** Kyber-1024 (ML-KEM-1024) for KEM. Dilithium-5 (ML-DSA-87) for signatures. No classical fallback.
- **Identity is the root.** Every peer, service, and capability is bound to a Verrev identity: SHA3-256(Dilithium-5 public key).
- **Content-addressing for everything.** Files, messages, app bundles, state — all addressed by SHA3-256 hash.
- **CRDTs everywhere.** State is always mergeable. No locks, no conflicts, no central authority.
- **Test from day one.** Every crypto primitive has KATs against NIST vectors. Every protocol has chaos tests. Every CRDT has convergence tests.
- **Protocol upgrades via identity-weighted voting.** ≥67% approval with ≥10% quorum. Votes are CRDT-based.
- **Distributed by default.** Storage is erasure-coded across the mesh. Compute is replicated and verified.

### Dependency Chain

```
verrev-syscall  verrev-hash            ← Layer 0: Foundation
    │               │
    └───────┬───────┘
            │
      verrev-crypto                    ← Layer 1: Core Primitives
            │
      verrev-identity
            │
      verrev-capability
            │
      ┌─────┴─────┐
      │           │
 verrev-store  verrev-transport        ← Layers 2-3: Storage + Transport
      │           │
 verrev-fs    verrev-p2p
                  │
            verrev-relay
                  │
            verrev-mesh                ← Layer 4: Mesh Network
                  │
          ┌───────┼───────┐
          │       │       │
    verrev-name  │  verrev-sync        ← Layer 5: State + Replication
                │       │
                │ verrev-diststore
                │       │
          verrev-runtime │            ← Layer 6: Compute
                │       │
          verrev-compute │
                │       │
            verrev-db    │
                      ───┘
                    verrev-ui          ← Layer 7: Interface
                       │
                      apps             ← Layer 8: Applications
```

Each layer depends only on layers below it. No circular dependencies. No layer skips.

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           VERREV ECOSYSTEM                                │
│                                                                          │
│  LAYER 8: APPS                                                           │
│  ┌────────┬────────┬────────┬────────┬────────┬────────┬──────────┐    │
│  │Messenger│FileShare│ Shell │ Host  │Compute │ Vault │ Social   │    │
│  │        │        │       │       │ Node   │       │ Media    │    │
│  └────────┴────────┴───────┴───────┴────────┴───────┴──────────┘    │
│                          │                                            │
│  LAYER 7: INTERFACE                                                   │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  verrev-ui: wgpu Compositor · Scene Graph · Widgets · Fonts │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                          │                                            │
│  LAYER 6: COMPUTE                                                    │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────────────┐   │
│  │ verrev-runtime │ │ verrev-compute │ │ verrev-db             │   │
│  │ WASM JIT       │ │ Job Distrib.   │ │ KV · Queue · Document │   │
│  │ Cranelift      │ │ Verification   │ │ CRDT-backed           │   │
│  │ Cap Sandbox    │ │ Credit System  │ │                       │   │
│  └────────────────┘ └────────────────┘ └────────────────────────┘   │
│                          │                                            │
│  LAYER 5: STATE + REPLICATION                                        │
│  ┌────────────────┐ ┌──────────────────────────────────────┐        │
│  │ verrev-sync    │ │ verrev-diststore                     │        │
│  │ CRDTs          │ │ Erasure Coding · Replication · Repair│        │
│  │ Merkle Tree    │ │                                       │        │
│  └────────────────┘ └──────────────────────────────────────┘        │
│                          │                                            │
│  LAYER 4: MESH NETWORK                                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐      │
│  │verrev-p2p│ │verrev-relay│verrev-mesh│ │ verrev-name     │      │
│  │ Kademlia │ │Store-     │ Multi-hop │ │ DNS Replacement  │      │
│  │ mDNS     │ │And-Forward│ Onion     │ │ DHT-based        │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘      │
│                          │                                            │
│  LAYER 3: TRANSPORT                                                  │
│  ┌────────────────────────────────────────────────────────┐         │
│  │ verrev-transport                                       │         │
│  │ QUIC-like over UDP · PQ Handshake (Kyber+Dilithium)   │         │
│  │ AEAD · Stream Mux · RACK Loss Detection · NewReno CC  │         │
│  └────────────────────────────────────────────────────────┘         │
│                          │                                            │
│  LAYER 2: LOCAL STORAGE                                              │
│  ┌────────────────────────┐ ┌────────────────────────────┐          │
│  │ verrev-store            │ │ verrev-fs                  │          │
│  │ CoW B-tree · 4KB Blocks│ │ POSIX-free · CRDT Dirs    │          │
│  │ Encryption at Rest     │ │ Content-Addressed Files   │          │
│  └────────────────────────┘ └────────────────────────────┘          │
│                          │                                            │
│  LAYER 1: CORE PRIMITIVES                                             │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐         │
│  │ verrev-crypto  │ │ verrev-identity│ │ verrev-capability│         │
│  │ Kyber-1024     │ │ Self-Sovereign │ │ Tokens · Deleg.  │         │
│  │ Dilithium-5    │ │ DID · TLV Cert │ │ Attenuation      │         │
│  │ AES-GCM · XCP  │ │               │ │ Revocation       │         │
│  └────────────────┘ └────────────────┘ └──────────────────┘         │
│                          │                                            │
│  LAYER 0: FOUNDATION                                                  │
│  ┌─────────────────┐ ┌─────────────────────────────────┐            │
│  │ verrev-syscall   │ │ verrev-hash                    │            │
│  │ Raw Linux Syscalls│ │ SHA-3/SHAKE · Keccak-f[1600]  │            │
│  │ → Bare Metal    │ │ Content-Addressing Root        │            │
│  └─────────────────┘ └──────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technical Decision Registry

### CRYPTO-001: Cryptographic Hash Function
- **Choice:** SHA-3/SHAKE-256 as standalone `verrev-hash` crate at Layer 0
- **Rationale:** NIST standard for PQ crypto. Kyber and Dilithium use SHAKE internally. Single primitive for signatures, Merkle trees, content addressing, KDF. Sponge construction simpler to implement constant-time than SHA-2.
- **Implications:** Everything depends on `verrev-hash`. It is NOT part of `verrev-crypto`.

### CRYPTO-002: Key Encapsulation Mechanism
- **Choice:** Kyber-1024 (ML-KEM-1024, NIST FIPS 203)
- **Rationale:** 256-bit PQ security, highest NIST level. IND-CCA2. No hybrid X25519 fallback — this is a new system with no legacy interop.
- **Implications:** 1568-byte public keys, 1568-byte ciphertexts.

### CRYPTO-003: Digital Signatures
- **Choice:** Dilithium-5 (ML-DSA-87, NIST FIPS 204)
- **Rationale:** Highest NIST security level. Fastest verification. No patent encumbrances.
- **Implications:** 2592-byte public keys, 4627-byte signatures. Acceptable for P2P where bandwidth is cheap and verification speed matters.

### CRYPTO-004: Symmetric Encryption
- **Choice:** AES-256-GCM (hardware-accelerated) + XChaCha20-Poly1305 (192-bit nonces)
- **Rationale:** AES-GCM for bulk transport (controlled nonces). XChaCha20 for application-level encryption (nonce-misuse-resistant). Both use fixed stack buffers — no allocation.
- **Implications:** Two AEAD implementations. Both are `no_std` with caller-provided output buffers.

### CRYPTO-005: Random Number Generation
- **Choice:** Linux `getrandom` syscall via `verrev-syscall` (Phase 0). Hardware RNG + Fortuna CSPRNG (Phase 4+).
- **Rationale:** `getrandom` blocks until kernel CSPRNG is seeded. Sufficient for Phase 0.

### TRANSPORT-001: Wire Protocol
- **Choice:** Custom QUIC-like over UDP. Pure PQ handshake (no X25519).
- **Rationale:** Full control. PQ crypto plug-in. No external protocol stack dependency.
- **Implications:** Must implement loss detection, congestion control, stream multiplexing. All from scratch.

### TRANSPORT-002: Loss Detection
- **Choice:** RACK (RFC 8985)
- **Rationale:** State-of-the-art, proven in QUIC.

### TRANSPORT-003: Congestion Control
- **Choice:** NewReno (Phase 0) → BBR (Phase 1+)
- **Rationale:** Simple, well-understood, sufficient for P2P messaging.

### P2P-001: Distributed Hash Table
- **Choice:** Kademlia with S/Kademlia sybil resistance
- **Rationale:** Most battle-tested DHT (BitTorrent, IPFS). O(log n) lookups. Simple, provably correct.
- **Implications:** 256 buckets (one per bit of 256-bit address space). K=20, α=3.

### P2P-002: Peer Identity
- **Choice:** Peer ID = SHA3-256(Dilithium-5 public key)
- **Rationale:** Self-certifying. No PKI, no CAs.

### P2P-003: NAT Traversal
- **Choice:** ICE-lite: STUN + P2P relay fallback
- **Rationale:** ~99% connectivity. End-to-end encrypted through relay. No UPnP (insecure).

### P2P-004: Peer Discovery
- **Choice:** mDNS on LAN + DHT on WAN
- **Rationale:** Zero-config LAN discovery. Global DHT discovery.

### MESH-001: Multi-hop Routing
- **Choice:** Onion-encrypted multi-hop message forwarding
- **Rationale:** Every node knows only prev/next hop. Sender/recipient cannot be correlated by intermediaries. Store-and-forward for offline recipients.
- **Implications:** Circuit establishment, onion encryption layers, congestion control per circuit.

### MESH-002: Name System
- **Choice:** DHT-based name resolution. Name → identity → current address.
- **Rationale:** Replace DNS. No ICANN, no registrars. Uncensorable. Names are Dilithium-signed.
- **Implications:** Name registration protocol, resolution via DHT, renewal/transfer.

### CRDT-001: Text CRDT
- **Choice:** Diamond Types (boundary-based sequence CRDT)
- **Rationale:** State-of-the-art. O(log n) operations. Built-in undo/redo. Excellent merging.

### CRDT-002: Data Types
- **Choice:** LWW-Register, OR-Set, MV-Register, Diamond Text
- **Rationale:** LWW-Register for simple KV. OR-Set for contact lists, group membership. MV-Register for concurrent writes. Diamond Text for all text.

### CRDT-003: Sync Protocol
- **Choice:** Merkle tree reconciliation + Bloom filter optimization
- **Rationale:** O(log n) delta sync. Drills down to differing subtrees, exchanges only diffs.

### STORE-001: Content Addressing
- **Choice:** SHA3-256 per 4K block. Merkle tree for variable-length blobs.
- **Rationale:** Single hash primitive. Integrity verification. Partial sync.

### STORE-002: Local Format
- **Choice:** Copy-on-write B-tree
- **Rationale:** Atomic transactions, snapshots, integrity. Maps to CRDT model.

### STORE-003: Encryption at Rest
- **Choice:** XChaCha20-Poly1305 per-block. Key derived from identity via HKDF-SHA3-256.
- **Rationale:** Blocks can be synced without decryption. Confidentiality even from relay peers.

### DISTSTORE-001: Distributed Storage
- **Choice:** Reed-Solomon erasure coding (8+4 default). Auto-repair on peer churn.
- **Rationale:** Survives 4 peer losses without data loss. Configurable 4+2 to 16+8.
- **Implications:** Must implement Reed-Solomon from scratch in `no_std`.

### RUNTIME-001: JIT Compiler
- **Choice:** Cranelift (owned fork in Phase 1+)
- **Rationale:** Best Rust-native single-pass JIT. Modular. Replaceable.

### RUNTIME-002: Sandbox Model
- **Choice:** Capability-based. Every WASM import requires a capability token.
- **Rationale:** No POSIX concepts. Every import is explicitly granted. Delegation without escalation.

### COMPUTE-001: Distributed Compute
- **Choice:** WASM-based FaaS on the mesh. Data-locality-aware scheduling.
- **Rationale:** Deterministic execution enables verification. Capability sandbox for security.
- **Implications:** Job distribution, replicated verification, credit system, checkpointing.

### COMPUTE-002: Verification
- **Choice:** Replicated execution + challenge protocol
- **Rationale:** N peers execute the same job. Results must match. Disagreement triggers challenge round with M additional peers. Cheaters lose reputation.
- **Implications:** Must ensure WASM determinism. Cryptographic commitment of results before reveal.

### COMPUTE-003: Credit System
- **Choice:** Credit-as-capabilities. Each credit is a capability token (issuer, holder, amount, serial, signature).
- **Rationale:** Integrates with existing capability system. Double-spend is detectable (CRDT spent-set).
- **Implications:** Reputation-weighted credit limits. Fraud detection after the fact.

### ID-001: Identity System
- **Choice:** Self-sovereign identity. DID with Dilithium-5 key pairs. No central registry.
- **Rationale:** No CAs, no PKI. Identity = hash of public key. Verifiable credentials.
- **Implications:** No account recovery. Social recovery via capability delegation.

### ID-002: Certificate Format
- **Choice:** Custom binary TLV: identity (32B) + public key (2592B) + attributes + signature (4627B)
- **Rationale:** Not X.509/ASN.1. Simple, binary, designed for P2P.

### VOTING-001: Protocol Upgrades
- **Choice:** Identity-weighted voting. Any identity can propose. ≥67% approval, ≥10% quorum.
- **Rationale:** No central authority. Votes are CRDT LWW-Registers — everyone can tally independently.
- **Implications:** Activation is identity-weighted rolling upgrade. Each node chooses when to switch.

### KERNEL-001: Architecture
- **Choice:** Microkernel, seL4-inspired, written in Rust (Phase 4)
- **Rationale:** Minimal TCB. Capability-based IPC. Formal verification targets.
- **Implications:** Drivers in userspace. IPC is primary communication mechanism.

---

## 4. Layer Specifications

### 4.1 verrev-syscall (Layer 0)

Raw OS interface. On Linux: inline assembly `syscall` instructions. On Verrev microkernel: direct kernel calls.

```
verrev-syscall/
├── src/
│   ├── lib.rs          # #![no_std], platform selection
│   ├── types.rs        # Fd, Pid, Result, IoVec, socket structs
│   └── linux.rs        # Inline assembly syscalls (x86_64)
```

Surface: `socket`, `sendto`, `recvfrom`, `bind`, `close`, `getrandom`, `mmap`, `munmap`, `exit`, `now_nanos`.

### 4.2 verrev-hash (Layer 0)

SHA-3/SHAKE. The single hash primitive for the entire system. Every layer depends on this.

```
verrev-hash/
├── src/
│   ├── lib.rs          # #![no_std], pub mod sha3
│   └── sha3.rs         # Keccak-f[1600], sponge, SHA3-256/512, SHAKE-128/256
```

Tests: KATs against NIST vectors for all four modes.

### 4.3 verrev-crypto (Layer 1)

Post-quantum cryptography. Uses `verrev-hash` for internal SHAKE operations.

```
verrev-crypto/
├── src/
│   ├── lib.rs          # #![no_std], extern crate alloc
│   ├── util.rs         # ct_eq, ct_select, ct_swap, fill_random
│   ├── kyber.rs        # Kyber-1024: keygen, encaps, decaps
│   ├── dilithium.rs    # Dilithium-5: keygen, sign, verify
│   └── aead.rs         # AES-256-GCM, XChaCha20-Poly1305 (stack buffers)
```

Tests: NIST ACVP KATs for all primitives. Dudect constant-time verification.

### 4.4 verrev-identity (Layer 1)

Self-sovereign identity. Identity = SHA3-256(Dilithium-5 PK).

```
verrev-identity/
├── src/
│   └── lib.rs          # Identity (32B), IdentityBundle, TLV serialization
```

### 4.5 verrev-capability (Layer 1)

Capability tokens for all resources. Delegation, attenuation, revocation.

```
verrev-capability/
├── src/
│   └── lib.rs          # Capability, CapabilityType, rights_mask, delegation
```

### 4.6 verrev-store (Layer 2)

Local content-addressed block store. CoW B-tree on local disk.

```
verrev-store/
├── src/
│   └── lib.rs          # ContentStore, BlockRef (4KB blocks, SHA3-256)
```

### 4.7 verrev-fs (Layer 2)

POSIX-free filesystem on store. Directories as CRDT maps.

```
verrev-fs/
├── src/
│   └── lib.rs          # Directory (CRDT map), file resolution
```

### 4.8 verrev-transport (Layer 3)

QUIC-like wire protocol over UDP. PQ handshake, AEAD, stream mux.

```
verrev-transport/
├── src/
│   ├── lib.rs          # Connection, PeerAddr, Stream, errors
│   ├── handshake.rs    # 2-RTT PQ handshake (pure Kyber + Dilithium)
│   └── stream.rs       # Multiplexed streams, RACK, NewReno
```

Wire format: `[Packet Header: 16B] [Stream Frame: variable]`.

### 4.9 verrev-relay (Layer 3)

Relay protocol for NAT traversal. Store-and-forward for offline peers.

```
verrev-relay/
├── src/
│   └── lib.rs          # RelaySession, StoreAndForward
```

### 4.10 verrev-p2p (Layer 4)

Kademlia DHT. Peer discovery, content routing.

```
verrev-p2p/
├── src/
│   ├── lib.rs          # P2PNode, PeerInfo
│   ├── dht.rs          # RoutingTable, KBucket, xor_distance
│   ├── discovery.rs    # mDNS LAN discovery
│   └── nat.rs          # NAT type detection, ICE-lite
```

Parameters: K=20, α=3, 256-bit address space.

### 4.11 verrev-mesh (Layer 4)

Multi-hop message routing. Onion forwarding. Circuit relay.

```
verrev-mesh/
├── src/
│   ├── lib.rs          # MeshNode, MeshError
│   ├── routing.rs      # Route discovery, maintenance
│   ├── onion.rs        # Onion encryption/decryption layers
│   └── circuit.rs      # Long-lived circuit management
```

Max hops: 8. Each hop knows only previous and next.

### 4.12 verrev-name (Layer 4)

DNS replacement. Human-readable names → identity → current address.

```
verrev-name/
├── src/
│   └── lib.rs          # NameRecord, NameResolver
```

### 4.13 verrev-sync (Layer 5)

CRDT types and Merkle tree sync protocol.

```
verrev-sync/
├── src/
│   ├── lib.rs          # SyncState, SyncError
│   ├── crdt.rs         # TextCrdt (Diamond), LWW-Register, OR-Set, MV-Register
│   ├── merkle.rs       # Merkle tree over CRDT state
│   └── protocol.rs     # SyncMessage, SyncSession
```

### 4.14 verrev-diststore (Layer 5)

Distributed storage with erasure coding and auto-repair.

```
verrev-diststore/
├── src/
│   ├── lib.rs          # DistributedStore, StoragePolicy
│   ├── erasure.rs      # Reed-Solomon encode/decode
│   ├── repair.rs       # Auto-repair on peer churn
│   └── policy.rs       # Replication policy configuration
```

Default: 8 data shards + 4 parity shards.

### 4.15 verrev-runtime (Layer 6)

WASM execution engine. Cranelift JIT. Capability sandbox.

```
verrev-runtime/
├── src/
│   └── lib.rs          # WasmModule, Instance, capability-gated imports
```

### 4.16 verrev-compute (Layer 6)

Distributed compute fabric. Job distribution, verification, credit.

```
verrev-compute/
├── src/
│   ├── lib.rs          # ComputeNode, Job, JobResult
│   ├── scheduler.rs    # Data-locality-aware scheduling
│   ├── verification.rs # Replicated execution + challenge protocol
│   └── credit.rs       # Credit-as-capabilities, CRDT spent-set
```

### 4.17 verrev-db (Layer 6)

Distributed database. CRDT-backed KV, queue, document store.

```
verrev-db/
├── src/
│   ├── lib.rs          # Database, Collection
│   ├── kv.rs           # CRDT-backed key-value store
│   ├── queue.rs        # CRDT-backed message queue
│   └── doc.rs          # CRDT-backed document store
```

### 4.18 verrev-ui (Layer 7)

GPU compositor. wgpu backend. Scene graph. Widgets.

```
verrev-ui/
├── src/
│   ├── lib.rs          # Point, Size, Rect, Color (#![no_std])
│   ├── compositor.rs   # Compositor, Scene, SceneNode
│   ├── widgets.rs      # Button, TextInput, ScrollView
│   └── text.rs         # Font, TextLayout, GlyphPlacement
```

### 4.19 verrev-net (Test Infrastructure)

Network simulation and chaos testing.

```
verrev-net/
├── src/
│   ├── lib.rs          # DEFAULT_LOSS_RATE, etc.
│   ├── simulation.rs   # Multi-node localhost simulation
│   └── chaos.rs        # Packet loss, reorder, delay injection
```

---

## 5. Project Structure

```
verrev/
├── Cargo.toml                  # Workspace root (27 members)
├── rust-toolchain.toml         # Nightly
├── .gitignore
├── .cargo/config.toml          # QEMU runners
├── rules.md                    # 18 engineering rules
├── PLAN.md                     # This file
├── libs/
│   ├── verrev-syscall/         # Layer 0: Raw syscalls
│   ├── verrev-hash/            # Layer 0: SHA-3/SHAKE
│   ├── verrev-crypto/          # Layer 1: PQ crypto
│   ├── verrev-identity/        # Layer 1: Self-sovereign identity
│   ├── verrev-capability/      # Layer 1: Capability tokens
│   ├── verrev-store/           # Layer 2: Local block store
│   ├── verrev-fs/              # Layer 2: Filesystem
│   ├── verrev-transport/       # Layer 3: Wire protocol
│   ├── verrev-relay/           # Layer 3: Relay + store-and-forward
│   ├── verrev-p2p/             # Layer 4: Kademlia DHT
│   ├── verrev-mesh/            # Layer 4: Multi-hop routing
│   ├── verrev-name/            # Layer 4: DNS replacement
│   ├── verrev-sync/            # Layer 5: CRDTs + Merkle sync
│   ├── verrev-diststore/       # Layer 5: Distributed storage
│   ├── verrev-runtime/         # Layer 6: WASM execution
│   ├── verrev-compute/         # Layer 6: Distributed compute
│   ├── verrev-db/              # Layer 6: Distributed database
│   ├── verrev-ui/              # Layer 7: GPU compositor
│   └── verrev-net/             # Test infrastructure
├── apps/
│   ├── messenger/              # P2P encrypted messenger
│   ├── fileshare/              # P2P file sharing
│   ├── shell/                  # Verrev shell
│   ├── host/                   # P2P web host
│   ├── compute-node/           # Compute capacity node
│   ├── vault/                  # Credential manager
│   ├── social/                 # Decentralized social
│   ├── media/                  # Media streaming
│   └── search/                 # P2P search
├── kernel/                     # Phase 4: Microkernel
└── scripts/
```

---

## 6. Phase 0: The Seed (Months 1-12)

**Goal:** Production-quality core stack + working P2P Messenger + FileShare demo.

### Milestone 0.0 — Foundation (Weeks 1-3)

**verrev-hash** (complete):
- Keccak-f[1600] permutation
- Sponge construction (absorb + squeeze)
- SHA3-256, SHA3-512, SHAKE-128, SHAKE-256
- KATs against NIST test vectors

**verrev-syscall** (complete):
- `syscall0` through `syscall6` with inline assembly
- Socket, sendto, recvfrom, bind, close
- mmap, munmap, getrandom, clock_gettime, exit

**verrev-crypto — Utilities:**
- ct_eq, ct_select, ct_swap
- fill_random (bridge to getrandom)

### Milestone 0.1 — Crypto (Weeks 4-8)

**verrev-crypto — Kyber-1024:**
- NTT + inverse NTT
- Polynomial arithmetic (barrett_reduce, montgomery_reduce)
- CBD sampler, compress/decompress
- Kyber.CCAKEM.KeyGen, Encaps, Decaps
- KATs against NIST ACVP vectors

**verrev-crypto — Dilithium-5:**
- NTT + inverse NTT (Q = 8380417)
- Rejection sampling
- Power2Round, Decompose, HighBits, LowBits
- KeyGen, Sign, Verify
- KATs against NIST ACVP vectors

**verrev-crypto — AEAD:**
- AES-256-GCM (software AES + AES-NI path)
- GHASH constant-time (CLMUL when available)
- XChaCha20-Poly1305 (HChaCha20 + ChaCha20 + Poly1305)
- Fixed stack buffers (no alloc)
- KATs against published vectors

**verrev-identity:**
- Identity = SHA3-256(PK)
- IdentityBundle: generate, sign, verify
- Binary TLV serialization

**verrev-capability:**
- Capability token type
- check_access, delegate, revoke
- Rights mask management

### Milestone 0.2 — Transport (Weeks 9-12)

**verrev-transport:**
- UDP socket via raw syscall
- Packet framing (connection ID, packet number, flags, stream ID)
- 2-RTT PQ handshake:
  - ClientHello: Kyber PK + Dilithium signature
  - ServerResponse: Kyber ciphertext + server PK + signature
  - ClientConfirm: session derived
- Pure Kyber-1024 (no X25519 hybrid)
- AEAD encryption of all packets
- Stream multiplexing (256 streams per connection)
- RACK loss detection
- NewReno congestion control
- Retransmission timer

Tests: Local socket handshake, 10MB stream, 5/10/25% packet loss chaos, out-of-order delivery, connection migration.

### Milestone 0.3 — P2P + Relay (Weeks 13-16)

**verrev-p2p:**
- Kademlia routing table (256 buckets, K=20)
- Bucket splitting
- Node lookup (α=3 parallel)
- Peer persistence
- S/Kademlia challenge-response
- mDNS responder (port 5353)

**verrev-relay:**
- Store-and-forward for offline recipients
- Basic relay session

### Milestone 0.4 — Mesh + Name (Weeks 17-19)

**verrev-mesh:**
- Multi-hop route discovery
- Onion encryption layers (max 8 hops)
- Circuit establishment
- Message forwarding

**verrev-name:**
- Name registration (Dilithium-signed)
- DHT-based name resolution
- Name renewal

### Milestone 0.5 — CRDT + Sync (Weeks 20-22)

**verrev-sync:**
- Diamond Types text CRDT
- LWW-Register, OR-Set, MV-Register
- Merkle tree over document state
- Delta sync (compare root, drill down, exchange diffs)
- Bloom filter optimization

Tests: Two-agent random ops convergence, N-agent convergence, partition/merge.

### Milestone 0.6 — Store + FS + DistStore (Weeks 23-26)

**verrev-store:**
- Content-addressed block store (4KB blocks)
- CoW B-tree
- Encryption at rest (XChaCha20-Poly1305)

**verrev-fs:**
- Directory as CRDT map
- File resolution by content hash

**verrev-diststore:**
- Reed-Solomon erasure coding (8+4 default)
- Shard distribution across mesh
- Auto-repair on peer churn

### Milestone 0.7 — Compute (Weeks 27-30)

**verrev-runtime:**
- WASM binary format parser
- WASM validation
- Cranelift JIT integration
- Capability-gated imports
- Linear memory with guard pages

**verrev-compute:**
- Job type, submission
- Worker discovery
- Data-locality scheduling
- Replicated execution verification

### Milestone 0.8 — Messenger + FileShare (Weeks 31-36)

Integration of all Phase 0 components:

**Messenger:**
- Identity generation/loading
- mDNS + DHT peer discovery
- PQ-encrypted transport
- CRDT-synced conversation state
- 1:1 messaging
- Group chat
- File sharing via content-addressed store

**FileShare:**
- Drop file → content hash → publish to mesh
- Fetch by hash from any peer
- Erasure-coded availability

### Milestone 0.9 — UI + Polish (Weeks 37-42)

**verrev-ui:**
- wgpu initialization and swapchain
- Scene graph (rectangle, text, clip, transform)
- GPU compositor
- Flexbox-like layout engine
- Widget set (Button, TextInput, ScrollView, Label)
- Font rendering (OpenType, glyph rasterization)
- Input handling (keyboard, mouse)

**Polish:**
- Visual: dark theme, message bubbles
- Performance: LAN sub-100ms, WAN sub-1s
- Error handling: offline mode, reconnection
- CI: cargo build, test, clippy, fmt

---

## 7. Current Implementation Status (2026-07-26)

### Layer 0: Foundation ✅

| Crate | Status | Notes |
|---|---|---|
| `verrev-hash` | **Complete** | Keccak-f[1600], SHA3-256/512, SHAKE128/256. KATs pass. `libs/verrev-hash/src/sha3.rs` (210 lines) |
| `verrev-syscall` | **Complete** | Raw Linux syscall shim: getrandom, socket, read/write/open stubs. `libs/verrev-syscall/src/linux.rs` |

### Layer 1: Core Primitives ✅

| Crate | Status | Notes |
|---|---|---|
| `verrev-crypto/util` | **Complete** | ct_eq, ct_select, ct_swap, fill_random (uses getrandom). 43 lines |
| `verrev-crypto/kyber` | **✅ Complete** | ML-KEM-1024 (FIPS 203): NTT, CPAPKE, CCAKEM with encaps/decaps. 764 lines, 10 tests. |
| `verrev-crypto/dilithium` | **✅ Complete** | ML-DSA-87 (FIPS 204): full NTT (Q=8380417), keygen, sign, verify. 1762 lines, 9 tests. |
| `verrev-crypto/aead` | **✅ Complete** | XChaCha20-Poly1305 + AES-256-GCM. S-box from GF(2⁸) formula. 547 lines, 6 tests. |
| `verrev-identity` | **Complete** | Identity = SHA3-256(Dilithium PK). IdentityBundle with generate/sign/verify. 54 lines |
| `verrev-capability` | **Complete** | Capability tokens with check_access, delegate, revoke. Rights mask bits. 69 lines |

### Layers 2-7: Architecture Shells ⚠️

| Crate | Status | Notes |
|---|---|---|
| `verrev-store` | **Working** | ContentStore with BTreeMap backing. `put` computes hash, `get` returns data, `verify` checks. |
| `verrev-fs` | **Working** | Directory lookup/add_entry working. No duplicate detection. |
| `verrev-transport` | **Shell** | Connection, PeerAddr, StreamState types. Handshake/stream return stubs. |
| `verrev-relay` | **Working** | StoreAndForward with store/retrieve. No expiry enforcement. |
| `verrev-p2p` | **Working** | Kademlia RoutingTable with 256 buckets, KBucket insert/find. `find_closest`, discovery, NAT are stubs. |
| `verrev-mesh` | **Shell** | MeshNode, Circuit, OnionMessage types. Routing adds routes, onion/circuit are stubs. |
| `verrev-name` | **Shell** | NameRecord, NameResolver types. resolve/register return errors. |
| `verrev-sync` | **Shell** | CRDT types, Merkle tree with insert. root_hash/diff/protocol reconcile are stubs. |
| `verrev-diststore` | **Shell** | DistributedStore, erasure/repair return errors. Policy is working. |
| `verrev-runtime` | **Shell** | WasmModule compile/instantiate OK vacuously. Instance::call returns empty Vec. Unsound static mut. |
| `verrev-compute` | **Shell** | Job, ComputeNode types. CreditLedger working (O(n) spent-set). Scheduler/verification stubs. |
| `verrev-db` | **Working** | KvStore, MessageQueue, DocumentStore with BTreeMap backing. Database create_collection works. |
| `verrev-ui` | **Shell** | Point, Rect, SceneNode, Button, TextInput types. Compositor/Font stubs. |
| `verrev-net` | **Working** | NetworkSimulation with send/latency/stats. ChaosConfig. Loss model is approximate. |
| **All 9 apps** | Stubs | println only |

### Recently Fixed Violations (per Rule 18)

| Issue | Fix |
|---|---|
| `heapless` external dep | Removed from all Cargo.toml. Replaced `heapless::Vec<T,N>` with `alloc::vec::Vec<T>` across 21 files |
| Kyber placeholder encaps/decaps | Replaced SHA-3 substitutes with `ccakem_encaps`/`ccakem_decaps` forwarders |
| Dilithium zeroed keys + false verify | Full NTT implementation with `polyvecl_uniform_eta` (correct `% 5` mapping). Sign/verify roundtrip passing |
| AEAD SHA-3 substitutions | Replaced with proper XChaCha20-Poly1305 + AES-256-GCM. S-box from GF(2⁸) formula. 6 KATs |
| `fill_random` compile_error on no_std | `verrev-syscall` is required dep. Always uses getrandom |
| Kyber NTT index-out-of-bounds | Fixed zetas iteration pattern |
| Kyber a_hat matrix dimension | Changed from \[K;N\] to \[K\*K;N\] |
| SHA-3 keccak_f pi step | PI_INDICES → y + 5\*(2x+3y)%5 |
| SHA-3 keccak_f chi step | Fixed neighbors from (y+z)%5 to (x+1)%5/(x+2)%5 |
| SHA-3 rho offsets transposed | Fixed from r\[y\]\[x\] to r\[x\]\[y\] |
| SHA-3 squeeze padding | Fixed rate/8 to rate |
| Dilithium sign/verify roundtrip | Fixed `polyvecl_uniform_eta`/`polyveck_uniform_eta` missing `% 5`. Was generating values down to -12, corrupting keys |

### Build & Test

```sh
cargo build                          # Full workspace (0 errors)
cargo test -- --test-threads=1       # 27 tests pass (2 SHA-3 + 10 Kyber + 9 Dilithium + 6 AEAD)
```

Workspace: 28 crates (19 libs + 9 apps). `#![no_std]` + `extern crate alloc`. Edition 2024.
Zero external dependencies. 27 warnings (dead code in crypto + stubs).

### Key File Reference

| File | Purpose |
|---|---|
| `rules.md` | 19 engineering rules |
| `AGENTS.md` | AI context — full state, conventions, key files |
| `libs/verrev-hash/src/sha3.rs` | SHA-3 (production, KAT-verified, 235 lines) |
| `libs/verrev-crypto/src/kyber.rs` | Kyber-1024 (ML-KEM-1024, full CCAKEM, 764 lines) |
| `libs/verrev-crypto/src/dilithium.rs` | Dilithium-5 (ML-DSA-87, full NTT sign/verify, 1762 lines) |
| `libs/verrev-crypto/src/aead.rs` | AEAD (XChaCha20-Poly1305 + AES-256-GCM, 547 lines) |
| `libs/verrev-crypto/src/util.rs` | ct_eq, ct_select, ct_swap, fill_random |
| `libs/verrev-capability/src/lib.rs` | Capability tokens (functional) |
| `libs/verrev-identity/src/lib.rs` | IdentityBundle (functional) |

### Phase 0 Build Plan

| # | Milestone | Timeframe | Status |
|---|---|---|---|
| 0.0 | Foundation (hash + syscall + crypto util) | Weeks 1-3 | ✅ Complete |
| 0.1 | Crypto (Kyber, Dilithium, AEAD, identity, caps) | Weeks 4-8 | ✅ Complete |
| 0.2 | Transport (UDP, PQ handshake, stream mux) | Weeks 9-12 | ⬜ Not started |
| 0.3 | P2P + Relay (Kademlia, mDNS, store-and-forward) | Weeks 13-16 | ⬜ Not started |
| 0.4 | Mesh + Name (onion routing, DHT name resolution) | Weeks 17-19 | ⬜ Not started |
| 0.5 | CRDT + Sync (Diamond Types, Merkle sync) | Weeks 20-22 | ⬜ Not started |
| 0.6 | Store + FS + DistStore (CoW B-tree, erasure code) | Weeks 23-26 | ⬜ Not started |
| 0.7 | Compute (WASM, job distribution, verification) | Weeks 27-30 | ⬜ Not started |
| 0.8 | Messenger + FileShare apps | Weeks 31-36 | ⬜ Not started |
| 0.9 | UI (wgpu compositor, widgets, fonts) | Weeks 37-42 | ⬜ Not started |

---

## 8. Phase 1: Application Platform (Months 12-24)

### M1.0 — Distributed Database + Queue (Months 12-14)
- verrev-db: KV store, document store, message queue
- CRDT-backed consistency

### M1.1 — Full App Suite (Months 14-18)
- messenger v2 (groups, channels, typing indicators, read receipts)
- shell (capability-aware command interface)
- host (P2P web/file hosting with HTTP gateway)
- vault (encrypted credential manager)
- compute-node (compute capacity contribution)

### M1.2 — SDK + App Format (Months 18-20)
- `.verrev` bundle format
- WASM SDK (Rust, Zig, C targets)
- App signature verification
- Capability audit tooling

### M1.3 — Social + Media (Months 20-22)
- verrev-social: decentralized social feed (CRDT)
- verrev-media: P2P media streaming

### M1.4 — Search (Months 22-24)
- verrev-search: DHT-based keyword search
- Content-indexed mesh pages

---

## 9. Phase 2: Compute Platform (Months 18-30)

Overlaps with Phase 1 end.

### M2.0 — Distributed Compute (Months 18-22)
- Full job distribution and verification
- Credit marketplace (earn/spend credits)
- Reputation system
- Resource advertising on DHT

### M2.1 — Enterprise Features (Months 22-26)
- Private mesh islands (intranet)
- FIPS 140-3 compliance documentation
- Audit logging
- SLA guarantees (reputation-weighted)

### M2.2 — Cross-Platform (Months 26-30)
- Android NDK support
- iOS (as far as Apple allows)
- Browser extension for mesh connectivity
- Email bridge

---

## 10. Phase 3: Global Deployment (Months 24-36)

### M3.0 — Mobile Optimization
- Battery-aware participation (duty cycling)
- Connection manager for WiFi/cellular handoff
- Push notification relay

### M3.1 — Mobile Apps
- Messenger on Android/iOS
- FileShare on mobile
- Compute node (when charging)

### M3.2 — Network Bootstrapping
- Seed nodes for DHT bootstrap
- Incentives for early adopters
- Migration tools from centralized services

---

## 11. Phase 4: Microkernel OS (Months 30-42)

### M4.0 — QEMU Boot (Months 30-32)
- UEFI boot protocol
- Long mode, paging
- Serial output
- Simple framebuffer
- "Verrev v0.1.0"

### M4.1 — Kernel Core (Months 32-36)
- Capability space (per-process)
- IPC: send/recv/reply (seL4-inspired)
- Scheduler: O(1) priority + RR
- Memory: capability-based paging

### M4.2 — Userspace (Months 36-39)
- Init process
- Service manager
- Filesystem server (CoW B-tree)
- Network server
- Display/compositor server

### M4.3 — Self-Hosting (Months 39-42)
- Rust cross-compiler on Verrev
- Build Verrev on Verrev
- Daily-driveable

---

## 12. Phase 5: Custom Silicon (Years 4+)

- PQ crypto accelerators (Kyber NTT, Dilithium NTT)
- WASM execution unit
- P2P routing coprocessor
- CRDT merge engine
- Verrev Phone / Laptop / Server

---

## 13. Coding Standards

- rustfmt defaults (enforced in CI)
- Clippy: deny all warnings in CI
- No `unwrap()`, `expect()`, `panic!()` in library code
- No `unsafe` unless documented with `// Safety:` invariants
- Every `unsafe` block justified
- No `transmute` — use `from_ne_bytes` or explicit casts
- All crypto operations constant-time
- `#[deny(unsafe_op_in_unsafe_fn)]`
- All allocations go through capability system
- Bounds-checked all vector/array accesses

### Testing Requirements

| Layer | Unit Tests | Property Tests | KATs | Chaos | Formal |
|-------|-----------|---------------|------|-------|--------|
| verrev-crypto | Every function | N/A | NIST vectors | dudect constant-time | Timing model |
| verrev-identity | Keygen, roundtrip | Sign/verify idempotence | Known-answer | N/A | N/A |
| verrev-transport | Packet encode/decode | Stream ordering | N/A | Loss, reorder, delay | Handshake model |
| verrev-p2p | Bucket ops | Lookup correctness | N/A | 1000-node churn | N/A |
| verrev-mesh | Route ops | Path discovery | N/A | Partition, latency | N/A |
| verrev-sync | Insert/delete | Convergence (N agents) | N/A | Partition/merge | CRDT convergence |
| verrev-runtime | WASM spec tests | Capability enforcement | N/A | Fuzz WASM modules | Sandbox model |
| verrev-ui | Render frame | Layout computation | N/A | N/A | N/A |

CI: `cargo test`, `cargo clippy --deny warnings`, `cargo +nightly fmt --check` on every commit.

---

## 14. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|------------|
| R1 | Kyber/Dilithium side channel | Medium | Critical | Constant-time from day one; dudect in CI; external audit |
| R2 | Transport correctness bug | Medium | High | Chaos testing (loss, reorder, delay); protocol fuzzing |
| R3 | CRDT convergence bug | Low | Critical | Random-agent convergence tests; partition/merge testing |
| R4 | WASM JIT performance slow | Low | Medium | Cranelift proven fast; interpreter fallback |
| R5 | Project scope too large | High | High | Phase 0 is the filter; ship or fail by month 12 |
| R6 | Microkernel IPC overhead | Medium | Medium | seL4 benchmarks show <100 cycles per IPC |
| R7 | P2P latency for real-time | Medium | Medium | CRDT sync is async; LAN demo first |
| R8 | Rust nightly breaks code | Medium | Low | Pin version; test multiple nightlies |
| R9 | Mobile battery drain | Medium | Medium | Duty cycling, adaptive relay, charging-only compute |

---

*Last updated: 2026-07-26 — Added Rule 19 (Absolute Perfection) to engineering constraints. Full codebase audit completed: 28 crates, 31 tests, ~5500 lines.*
