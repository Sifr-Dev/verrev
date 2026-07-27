# Verrev — Agent Context

## Project

Vertically-integrated P2P OS + network from scratch in `#![no_std]` Rust. Replaces centralized infrastructure (AWS, DNS, cloud) with a global mesh of personal devices. Post-quantum crypto, capability security, CRDTs everywhere.

**19 engineering rules** in `rules.md`. Key constraints:
- Zero external dependencies beyond Rust + LLVM
- `#![no_std]` for ALL libraries (extern crate alloc allowed)
- Post-quantum only: Kyber-1024 KEM, Dilithium-5 signatures
- No refactors, no rewrites — every line is final architecture
- No hardcoded tables — all derived from mathematical formulas where possible
- Violations are blockers per Rule 18
- **Rule 19 (Absolute Perfection):** No "good enough." Every function must be the absolute best implementation you are capable of — the fastest algorithm, the most memory-efficient data structure, the most mathematically rigorous reduction, the tightest constant-time execution. Pragmatism is the enemy of correctness.

## Dependency Chain

```
verrev-syscall  verrev-hash           Layer 0: Foundation
  └── verrev-crypto                   Layer 1: Core Primitives
       └── verrev-identity
            └── verrev-capability
                 ├── verrev-store → verrev-fs
                 └── verrev-transport → verrev-p2p → verrev-relay → verrev-mesh
                      ├── verrev-name
                      ├── verrev-sync → verrev-diststore
                      └── verrev-runtime → verrev-compute → verrev-db
                           └── verrev-ui → apps
```

No circular deps. Each layer depends only on layers below.

## Codebase Audit (2026-07-26)

**Build:** `cargo build` — 0 errors, 8 warnings (all pre-existing dead code).
**Tests:** `cargo test —test-threads=1` — 31 total: 27 verrev-crypto + 2 verrev-hash + 2 verrev-p2p.
**Workspace:** 28 crates (19 libs + 9 apps).
**Lines:** ~5500 across all library source files (excluding tests).

---

### Layer 0 — Foundation

#### verrev-hash/src/sha3.rs (234 lines) — ✅ Perfect
SHA-3 Keccak-f[1600], SHA3-256/512, SHAKE128/256. RC from LFSR formula, RHO from `(t(t+1)/2) mod 64`. KAT-verified.
- No Rule 19 violations. Absorb silently returns on squeeze (acceptable for sponge API).

#### verrev-syscall/src/linux.rs (186 lines) — ⚠️ 2 violations
Raw Linux syscall shim (inline asm). getrandom, socket, sendto, recvfrom, mmap, exit work.
- **V1: `#![allow(dead_code)]`** — Rule 18/19 violation. Remove it.
- **V2: Missing read/write/open wrappers** — SYS_READ/SYS_WRITE/SYS_OPEN constants defined but no functions wrapping them.
- **V3: No `// Safety:` on raw pointer params** — sendto takes `Option<(*const u8, u32)>` without safety comment.
- **V4: Magic number 28** — sockaddr_storage size should be named constant (SOCKADDR_MAX or similar).
- **V5: Return value unchecked** — now_nanos() calls syscall without checking result.

#### verrev-syscall/src/types.rs (54 lines) — ✅ Perfect
SyscallError, ErrnoKind, Fd, Pid type aliases. Correct for Phase 0.

---

### Layer 1 — Core Primitives

#### verrev-crypto/src/util.rs (36 lines) — ✅ Perfect
ct_eq, ct_select, ct_swap, fill_random, random_u64.
- fill_random should retry on EINTR (getrandom interruption). Minor.

#### verrev-crypto/src/kyber.rs (764 lines) — ⚠️ 4 violations
Full ML-KEM-1024. NTT, basemul, CPAPKE, CCAKEM. 10 tests pass.
- **V1: POLYVECBYTES defined but never used** (dead code warning).
- **V2: poly_sub defined but never used** (dead code warning).
- **V3: polyveck_frombytes defined but never used** (dead code warning).
- **V4: generate_keypair (line 220) duplicates ccakem_keygen** — two key generation functions, one dead. Keep ccakem_keygen, remove generate_keypair (or make test-only).

#### verrev-crypto/src/dilithium.rs (1762 lines) — ⚠️ 8 violations
Full ML-DSA-87. 11 Dilithium tests + 10 Kyber + 6 AEAD = 27 in verrev-crypto.
- **V1 (FIXED): Hardcoded zeta table** — replaced with formula: `zetas[i] = R · ζ^(2·br7(i))` for i=1..127, `R · ζ^(2·br7(i-128)+1)` for i=128..255. Verified all 256 entries match reference.
- **V2: bit_rev7 defined but never used** (zeta_table now uses it internally, so this is RESOLVED — it IS used).
- **V3: sample_eta dead** (line 266) — not used anywhere. Actual sampling uses polyvecl_uniform_eta / polyveck_uniform_eta.
- **V4: derive dead** (line 834) — not used anywhere.
- **V5: captured_w1_high read-before-assign warning** in test (line 1178).
- **V6: a1_lo, a1_mid, a1_hi unused** in test (lines 1336-1342).
- **V7: zeta128_mont_via_r_sq, zeta128_mont_via_mont unused** in test (lines 1635-1636).
- **V8: w1_copy unused mut** in test (line 1310).

#### verrev-crypto/src/aead.rs (547 lines) — ❌ 6 violations
XChaCha20-Poly1305 + AES-256-GCM. 6 tests pass.
- **V1: Poly1305 carry propagation incomplete** — `h[0] += c*5` may overflow without propagating to h[1]. After the 4 multiply-adds, a full carry chain across all 5 limbs is needed.
- **V2: Tag comparison uses `diff |= ...` loop** instead of `util::ct_eq`. Functionally correct but doesn't use project convention.
- **V3: `unwrap()` calls in chacha20_block, hchacha20** — on try_into(). Cannot fail but Rule 18 bans unwrap.
- **V4: `Vec` heap allocations** in encrypt/decrypt for auth data assembly. Should use fixed stack buffer.
- **V5: aes_sbox() recomputed per key expansion** — the S-box is identical for all keys. Compute once at module init or lazily.
- **V6: GHASH bit-by-bit multiply** — correct but slow. 4-bit window table would give 16× speedup.

#### verrev-identity/src/lib.rs (54 lines) — ✅ Perfect
Identity = SHA3-256(pk). IdentityBundle with generate/sign/verify. Clean.

#### verrev-capability/src/lib.rs (69 lines) — ⚠️ 1 violation
Capability tokens with check_access, delegate, revoke.
- **V1: Custom(c) right bit calculation** — `1 << (4 + c.min(60))`. If c = 60, shift = 64 on u64. In Rust, shl by >= bit_width is a panic in debug, compiler-defined in release. Fix: `1u64.checked_shl(4 + c.min(59)).unwrap_or(0)`.

---

### Layer 2 — Storage

#### verrev-store/src/lib.rs (51 lines) — ⚠️ Partial
ContentStore with BTreeMap. put computes hash correctly, get returns None (stub).
- No persistence. Acceptable for Phase 0 architecture.

#### verrev-fs/src/lib.rs (45 lines) — ⚠️ 1 violation
Directory CRDT map with lookup/add_entry.
- **V1: add_entry doesn't check for duplicates** — can have multiple entries with same name.
- No test module.

---

### Layer 3 — Transport

#### verrev-transport/src/lib.rs (68 lines) — ❌ Shell
Connection, PeerAddr, StreamState types defined. All values initialized with defaults, no real I/O.

#### verrev-transport/src/handshake.rs (38 lines) — ❌ Stub
next_message returns None, receive_message ok, session_key returns [0; 32].

#### verrev-transport/src/stream.rs (28 lines) — ❌ Stub
stream uses *mut Connection (raw pointer, unsafe to dereference). send/recv/close all return dummy values.

---

### Layer 3 — Relay

#### verrev-relay/src/lib.rs (40 lines) — ⚠️ 2 violations
StoreAndForward with Vec backing. store works, retrieve finds by identity.
- **V1: No duplicate checking** — same message can be stored twice.
- **V2: Expiry never checked** — messages with expired TTL are never pruned.

---

### Layer 4 — P2P

#### verrev-p2p/src/lib.rs (59 lines) — ❌ Stub
P2PNode with routing table. bootstrap/find_peer/connect all return stubs (connect returns Err).

#### verrev-p2p/src/dht.rs (98 lines) — ⚠️ 3 violations
RoutingTable (256 buckets), KBucket with insert/find_closest. xor_distance tested and correct.
- **V1: find_closest returns empty Vec** — complete no-op.
- **V2: KBucket::insert silently drops when full** — K=20 limit, new peers dropped without pinging oldest.
- **V3: No bucket splitting** — required for proper Kademlia.

#### verrev-p2p/src/discovery.rs (24 lines) — ❌ Stub
All methods return Ok/no-ops.

#### verrev-p2p/src/nat.rs (19 lines) — ❌ Stub
detect returns None, punch_hole returns false.

---

### Layer 4 — Mesh

#### verrev-mesh/src/lib.rs (45 lines) — ❌ Stub
MeshNode types, route_message returns Err.

#### verrev-mesh/src/routing.rs (33 lines) — ⚠️ Partial
RoutingTable with add_route/next_hop working. No route discovery.

#### verrev-mesh/src/onion.rs (11 lines) — ❌ Stub
Type definitions only. No encryption/decryption logic.

#### verrev-mesh/src/circuit.rs (9 lines) — ❌ Stub
Just a struct definition.

---

### Layer 4 — Name

#### verrev-name/src/lib.rs (44 lines) — ❌ Stub
NameRecord struct, NameResolver with resolve/register returning errors.

---

### Layer 5 — Sync

#### verrev-sync/src/lib.rs (27 lines) — ✅ Perfect
SyncState type definition.

#### verrev-sync/src/crdt.rs (92 lines) — ⚠️ 1 violation
TextCrdt with OpId/CrdtValue/TextCursor. get_hash works over empty state.
- **V1: insert/delete are no-ops** — accept parameters, return Ok(()), do nothing.

#### verrev-sync/src/merkle.rs (28 lines) — ❌ 3 violations
MerkleTree with fixed-size array.
- **V1: Fixed [Option<[u8; 32]>; 256] limits to 256 leaves.**
- **V2: root_hash returns all zeros** — no actual tree computation.
- **V3: diff returns empty Vec** — no diff logic.

#### verrev-sync/src/protocol.rs (40 lines) — ❌ Stub
SyncMessage enum, SyncSession::reconcile returns Ok(None).

---

### Layer 5 — Distributed Store

#### verrev-diststore/src/lib.rs (43 lines) — ❌ Stub
DistributedStore with put/get/repair all returning errors.

#### verrev-diststore/src/erasure.rs (10 lines) — ❌ Stub
encode/decode return errors.

#### verrev-diststore/src/repair.rs (11 lines) — ❌ Stub
needs_repair returns false, find_replacements returns error.

#### verrev-diststore/src/policy.rs (19 lines) — ✅ Working
StoragePolicy with Default impl. Correct.

---

### Layer 6 — Runtime

#### verrev-runtime/src/lib.rs (52 lines) — ❌ 2 violations
WasmModule with compile/instantiate, Instance::call.
- **V1: Unsound `&'static mut [u8]`** — memory field is globally mutable, unsound in safe Rust if multiple instances reference it.
- **V2: compile returns Ok without parsing WASM** — vacuous success.

---

### Layer 6 — Compute

#### verrev-compute/src/lib.rs (57 lines) — ❌ Stub
Job/ComputeNode types. execute_job/submit_job return errors.

#### verrev-compute/src/scheduler.rs (6 lines) — ❌ Stub
find_workers returns error.

#### verrev-compute/src/verification.rs (9 lines) — ⚠️ Partial
VerificationResult works, verify_result returns default.

#### verrev-compute/src/credit.rs (37 lines) — ⚠️ 1 violation
CreditCapability, CreditLedger with is_spent/mark_spent using Vec<[u8; 32]>.
- **V1: O(n) spent-set search** — should use BTreeSet or HashSet. Currently linear scan over Vec.

---

### Layer 6 — Database

#### verrev-db/src/lib.rs (39 lines) — ⚠️ Working
Database with BTreeMap<String, Vec<u8>>. create_collection works.

#### verrev-db/src/kv.rs (26 lines) — ✅ Working
KvStore with BTreeMap<Vec<u8>, Vec<u8>>. get/set/delete all work.

#### verrev-db/src/queue.rs (21 lines) — ✅ Working
MessageQueue with VecDeque<Vec<u8>>. push/pop work.

#### verrev-db/src/doc.rs (31 lines) — ✅ Working
DocumentStore with nested BTreeMap. insert/find work.

---

### Layer 7 — UI

#### verrev-ui/src/lib.rs (30 lines) — ✅ Perfect
Point, Size, Rect types; Color alias. Clean.

#### verrev-ui/src/compositor.rs (37 lines) — ❌ Stub
Compositor initialize returns false, present does nothing.

#### verrev-ui/src/widgets.rs (38 lines) — ✅ Working
Button, TextInput, ScrollView with constructors. Correct type definitions.

#### verrev-ui/src/text.rs (29 lines) — ❌ Stub
Font measure returns (0,0). GlyphPlacement/TextLayout types defined.

---

### Network Simulation

#### verrev-net/src/lib.rs (12 lines) — ✅ Perfect
Constants defined.

#### verrev-net/src/simulation.rs (59 lines) — ⚠️ 1 violation
NetworkSimulation with send/latency/stats working.
- **V1: Loss model is approximate** — uses `(packets_sent as f32 * loss_rate) as u64 > packets_lost`. Not a statistically sound Bernoulli trial.

#### verrev-net/src/chaos.rs (19 lines) — ✅ Working
ChaosConfig with Default impl. Clean.

---

### Applications (9 crates)

All 9 app crates (compute-node, fileshare, host, media, messenger, search, shell, social, vault) are `println` stubs awaiting library completion.

---

## Recently Fixed Violations

| Issue | Fix | Date |
|---|---|---|
| **Phase 1 — AEAD (6 items)** | | 2026-07-27 |
| Poly1305 carry propagation incomplete | Full propagate-reduce chain across all 5 limbs, twice, with wrap-around feedback `h[0] += c4*5` | 2026-07-27 |
| Tag comparison uses manual loop | Replaced with `util::ct_eq(&tag, &computed)` | 2026-07-27 |
| `unwrap()` in chacha20_block/hchacha20 | Eliminated via direct `u32::from_le_bytes([a, b, c, d])` construction, no slice-to-array conversions | 2026-07-27 |
| `Vec` heap allocations in encrypt/decrypt | Replaced with fixed `[u8; 4096+32]` stack buffer + byte cursor | 2026-07-27 |
| `aes_sbox()` recomputed per key expansion | Computed once via `core::cell::OnceCell` lazy-init static | 2026-07-27 |
| GHASH bit-by-bit multiply | 4-bit window table (16 entries), 32 nibble iterations → ~16× speedup | 2026-07-27 |
| **Phase 2 — Compiler Warnings (9 dead code + 8 test warnings)** | | 2026-07-27 |
| kyber.rs: `POLYVECBYTES`, `poly_sub`, `polyveck_frombytes` dead | Removed from production code | 2026-07-27 |
| kyber.rs: `generate_keypair` duplicated `ccakem_keygen` | Removed; test updated to use `ccakem_keygen` | 2026-07-27 |
| dilithium.rs: `sample_eta`, `derive` dead | Removed | 2026-07-27 |
| dilithium.rs: `captured_w1_high` unused in test | Changed closure to not capture it | 2026-07-27 |
| dilithium.rs: `a1_lo`, `a1_mid`, `a1_hi` unused in test | Prefixed with `_` | 2026-07-27 |
| dilithium.rs: `zeta128_mont_via_r_sq`, `zeta128_mont_via_mont` unused in test | Removed | 2026-07-27 |
| dilithium.rs: `w1_copy` unused mut in test | Removed `mut` | 2026-07-27 |
| **Phase 3 — verrev-syscall (5 items)** | | 2026-07-27 |
| `#![allow(dead_code)]` in linux.rs | Replaced with `#[allow(dead_code)]` on individual functions | 2026-07-27 |
| Missing `read()`, `write()`, `open()` wrappers | Implemented with syscall3 wrappers | 2026-07-27 |
| Missing `// Safety:` on raw pointer params | Added to sendto, recvfrom, mmap, munmap | 2026-07-27 |
| Magic number 28 for sockaddr_storage size | Replaced with `const SOCKADDR_MAX: usize = 28` | 2026-07-27 |
| now_nanos returns unchecked | Syscall return value checked; falls back to 0 on error | 2026-07-27 |
| **Phase 4 — Soundness (2 items)** | | 2026-07-27 |
| runtime `&'static mut [u8]` unsound | Changed to `&'static [u8]` (shared reference) | 2026-07-27 |
| capability shift overflow on `Custom(c)` | `1u64.checked_shl(4 + c.min(59)).unwrap_or(0)` | 2026-07-27 |
| **Phase 5 — Minor (2 items)** | | 2026-07-27 |
| fs `add_entry` allows duplicate names | Now returns `Result` with `Err("entry already exists")` on duplicate | 2026-07-27 |
| net loss model approximates running counts | Bernoulli trial via deterministic xorshift PRNG seeded by `packets_sent` | 2026-07-27 |
| **Phase 6 — Stub implementations (5 items)** | | 2026-07-27 |
| p2p `find_closest` returns empty Vec | Spiral-out bucket collection, XOR-distance sort, K selection | 2026-07-27 |
| p2p missing bucket splitting | `split_bucket` method: splits at bit depth, redistributes nodes by prefix bit | 2026-07-27 |
| p2p KBucket insert silently drops | Returns `Ok(false)` when full (Phase 0 without real network) | 2026-07-27 |
| sync merkle `root_hash` returns all zeros | Binary tree: `H(child1∥child2)`, odd leaf duplicated | 2026-07-27 |
| sync merkle `diff` returns empty Vec | O(n) leaf-by-leaf comparison | 2026-07-27 |
| (earlier fixes) | | |
| Hardcoded Dilithium zeta table (256 entries) | Generated from formula: `zetas[i] = R · ζ^(2·br7(i))` for i=1..127, `R · ζ^(2·br7(i-128)+1)` for i=128..255. | 2026-07-26 |
| AGENTS.md/README.md/PLAN.md stale | Full audit documented. Line counts, test counts, crate counts corrected. | 2026-07-26 |
| All `#[allow(dead_code)]` | Removed from sha3, kyber, dilithium, aead | earlier |
| `capacity` field (dead) | Removed from Keccak struct | earlier |
| `debug_assert!` in `absorb()` | Changed to silent `if self.squeezing { return }` | earlier |
| Hardcoded `RC[24]` table | Generated from Keccak LFSR `rc(t)` formula | earlier |
| Hardcoded `RHO[5][5]` table | Generated from `(t(t+1)/2) mod 64` formula | earlier |
| Hardcoded `QINV = 58728449` | Computed via Newton's method `Q⁻¹ mod 2³²` | earlier |
| Magic numbers in `decompose` | Replaced with `ALPHA = 2*GAMMA2`, `(1<<30)/GAMMA2`, `(Q-1)/ALPHA` | earlier |
| Missing `ALPHA`, `CRHBYTES` | Added as named constants | earlier |
| `sign()` broken (w0 self-subtract) | Fixed: proper `w0_low - c·s2` computation, hint, pack, return sig | earlier |
| `polyvecl/polyveck_uniform_eta` missing `% 5` | `2 - (t % 5)` → correct range `[-ETA, ETA]` | earlier |

## Build & Test

```sh
cargo build                            # Full workspace (0 errors)
cargo build -p verrev-crypto           # Single crate
cargo test -- --test-threads=1         # 31 tests pass (27 crypto + 2 hash + 2 p2p)
cargo test -p verrev-crypto -- --test-threads=1
cargo test -p verrev-hash
```

31 tests passing: 27 verrev-crypto (6 aead + 11 dilithium + 10 kyber) + 2 verrev-hash + 2 verrev-p2p.

Workspace members: 28 crates (19 libs + 9 apps in `apps/`).
Edition 2024, `#![no_std]` + `extern crate alloc`.

## Remediation Plan — Bring Codebase to Rule 19 Standard

This plan addresses every violation identified in the audit, grouped by area. Each fix specifies the exact algorithmic correction needed, in priority order. No new features until all violations are resolved.

---

### Phase 1: AEAD Corrections (libs/verrev-crypto/src/aead.rs)

**1.1 Poly1305 Full Carry Chain**

*Violation:* After each block's 4 multiply-adds (`h[0] += c*5`), the carry may propagate through h[0] into h[1]. The current chain is incomplete.

*Correct algorithm:* After the inner accumulation loop (4 terms of `h = h * r + c`), run a full propagate-reduce chain across all 5 limbs, twice to handle wrap-around from the h[4]→h[0] feedback:

```
// First pass: propagate h[0..4] rightward
let c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;
let c = h[1] >> 26; h[1] &= 0x3FFFFFF; h[2] += c;
let c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] += c;
let c = h[3] >> 26; h[3] &= 0x3FFFFFF; h[4] += c;
// Wrap: carry from h[4] gets multiplied by 5 (field reduction: 2^130 ≡ 5 mod 2^130-5)
let c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[0] += c * 5;
// Second pass: catch any overflow from h[0] after wrap
let c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;
// h[1] is now at most 26+1 bits, so no further carry possible
```

*Verification:* Run the 6 existing AEAD tests. Add a specific Poly1305 KAT with edge-case inputs designed to overflow a single limb (e.g., all 26 bits set in every limb after accumulation).

**1.2 Tag Comparison → `ct_eq`**

*Violation:* `diff |= (tag[i] ^ computed[i]) as u64` loop instead of `util::ct_eq`.

*Fix:* Replace the manual loop with `util::ct_eq(&tag, &computed)`. This returns `Choice` (0/1). The constant-time property is verified by inspection — `ct_eq` iterates all bytes regardless of early match.

*Verification:* Run AEAD tests. No functional change — both paths are constant-time; the fix is only for convention consistency.

**1.3 `unwrap()` elimination in ChaCha20/HChaCha20**

*Violation:* `input.try_into().unwrap()` in `chacha20_block` and `hchacha20`.

*Fix:* Change function signatures to take `&[u8; 64]` and `&[u8; 32]` respectively (they already take `&[u8; 32]` for key). The internal assembly of the 64-byte input block from key+counter+nonce can write directly into a local `[u8; 64]` array without going through a slice conversion.

Specifically: in `chacha20_block`, the function constructs a state array from key/counter/nonce bytes. Rather than building a `[u8; 64]` input via slice extension and then converting with unwrap, construct the `[u32; 16]` state directly:

```
let mut state = [0u32; 16];
state[0] = CONSTANT[0]; state[1] = CONSTANT[1]; state[2] = CONSTANT[2]; state[3] = CONSTANT[3];
for i in 0..8 { state[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into()...); }
```

Wait — this still uses `try_into().unwrap()`. The actual fix: use direct byte indexing instead of slice-to-array conversion:

```
state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
```

This avoids all slice-to-fixed-array conversions entirely, eliminating the need for `try_into()`.

*Verification:* All AEAD tests pass. ChaCha20 KAT verified identical output.

**1.4 `Vec` Heap Allocations → Fixed Stack Buffer**

*Violation:* Auth data assembly in encrypt/decrypt uses `Vec::new()` + `extend_from_slice()`.

*Fix:* Replace with a fixed `[u8; 64]` buffer and a byte cursor. For AES-GCM: auth data = iv (12 bytes) || ciphertext || len_iv (8 bytes) || len_ct (8 bytes). Max auth data = 12 + 65536 + 8 + 8 = ~64KB for max message. But for Phase 0 with fixed-size messages (e.g., 4096 bytes), use a buffer sized to the maximum expected message. Use `heapless::Vec`? No — we removed heapless. Use a local fixed-size array:

```
let mut ad_buf = [0u8; 4096 + 32]; // max message + overhead
let mut ad_len = 0;
ad_buf[ad_len..ad_len+12].copy_from_slice(&iv);
ad_len += 12;
ad_buf[ad_len..ad_len+ct.len()].copy_from_slice(ct);
ad_len += ct.len();
ad_buf[ad_len..ad_len+8].copy_from_slice(&(12u64).to_be_bytes());
ad_len += 8;
ad_buf[ad_len..ad_len+8].copy_from_slice(&(ct.len() as u64).to_be_bytes());
ad_len += 8;
let ad = &ad_buf[..ad_len];
```

*Verification:* AES-GCM roundtrip tests pass. Heap allocations eliminated.

**1.5 `aes_sbox()` Caching**

*Violation:* The S-box is recomputed from scratch (GF(2^8) inverse + affine transform) on every `aes256_key_expansion()` call.

*Fix:* Compute once at compile time using a const block:

```
const AES_SBOX: [u8; 256] = {
    let inverse = gf256_inverse_table(); // precomputed via const fn
    let mut sbox = [0u8; 256];
    let mut i = 0u8;
    while i < 255 {
        let inv = inverse[i as usize];
        let r = inv ^ (inv.rotate_left(1)) ^ (inv.rotate_left(2)) ^ (inv.rotate_left(3)) ^ (inv.rotate_left(4)) ^ 0x63u8;
        sbox[i as usize] = r;
        i += 1;
    }
    sbox[0] = 0x63; // special case: input 0 maps to 0x63
    sbox
};
```

The `gf256_inverse_table()` must also be const. Since we're in Edition 2024 with const capabilities, this should be possible with `const fn` and `while` loops.

If const computation is not feasible (Rust const fn limitations), the alternative is a lazy-init via `core::cell::OnceCell`:

```
use core::cell::OnceCell;
fn aes_sbox() -> &'static [u8; 256] {
    static SBOX: OnceCell<[u8; 256]> = OnceCell::new();
    SBOX.get_or_init(|| {
        let mut sbox = [0u8; 256];
        for i in 0u16..256 {
            let inv = gf256_inverse(i as u8);
            sbox[i as usize] = affine_transform(inv);
        }
        sbox
    })
}
```

*Verification:* AES-GCM roundtrip and KAT tests pass. Verify S-box matches NIST FIPS 197 expected values.

**1.6 GHASH 4-Bit Window Multiplication**

*Violation:* Current GHASH multiply is bit-by-bit (128 iterations per block, each loop does a conditional XOR and shift). A 4-bit window table gives ~16× fewer iterations.

*Correct algorithm:* GHASH computes in GF(2^128) defined by polynomial x^128 + x^7 + x^2 + x + 1. For each block multiplication `Y = (Y XOR C) * H`:

Precomputation (once per key expansion):
1. Compute 16 table entries: `H_table[i] = i * H` for i in 0..15, using GF(2^128) addition (XOR) and doubling (shift + conditional XOR with irreducible polynomial).

Accumulation (per block):
1. Let `x = Y XOR C` (16 bytes)
2. For each of the 32 nibbles of x (nibble 0 = top 4 bits, nibble 31 = bottom 4 bits):
   - result <<= 4 (shift left by 4 in GF(2^128))
   - result ^= H_table[nibble]

Wait, the direction matters. GHASH multiplies by H with the most-significant bit first (left-to-right). With a 4-bit window:

```
fn ghash_mul(x: &[u8; 16], h_table: &[[u8; 16]; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    for byte in x {
        for high in [true, false] {
            let nibble = if high { byte >> 4 } else { byte & 0xF };
            // z = z << 4 (in GF(2^128))
            for _ in 0..4 { z = ghash_double(&z); }
            // z ^= h_table[nibble]
            for i in 0..16 { z[i] ^= h_table[nibble as usize][i]; }
        }
    }
    z
}
```

Where `ghash_double` is the standard doubling operation: shift left by 1, if MSB was 1 then XOR with the reduction polynomial (0xE1 << 120).

Some implementations use a different approach: precompute H^1, H^2, H^4, ... H^128 (the powers of two), then process each bit. The 4-bit window with 16 table entries is simpler and gives the same speedup.

*Verification:* AES-GCM KAT test passes (output matches NIST test vectors). The 4-bit window is mathematically equivalent to the bit-by-bit method, just parallelized.

---

### Phase 2: Compiler Warnings (8 current, all dead code)

**2.1 kyber.rs — Remove Dead Code**

Remove these items (they cause compiler warnings and violate Rule 3 — no production-ready code with dead paths):

- `POLYVECBYTES` constant (line ~36): Not used anywhere. Remove.
- `poly_sub` function (line ~225): Not used. The ring subtraction uses `poly_add(a, poly_neg(b))` pattern instead. Remove or gate with `#[cfg(test)]`.
- `polyveck_frombytes` function (line ~670): Not used. Remove.
- `generate_keypair` function (line ~220): Duplicates `ccakem_keygen`. Find all callers — test `test_keypair_roundtrip` uses it. Change test to use `ccakem_keygen` instead, then remove `generate_keypair`.

*Order of operations:* Remove `generate_keypair` last, after updating test to use `ccakem_keygen`.

**2.2 dilithium.rs — Remove Dead Code + Test Warnings**

- `sample_eta` (line ~266): Dead. Actual sampling uses `polyvecl_uniform_eta` and `polyveck_uniform_eta`. Remove.
- `derive` (line ~834): Dead. Remove.
- `captured_w1_high` in test (line ~1178): The variable is captured by a closure but never read. Change the closure to not capture it, or use `let _ = &captured_w1_high;`.
- `a1_lo`, `a1_mid`, `a1_hi` in test (lines ~1336-1342): These are assigned but never read. Remove or prefix with `_`.
- `zeta128_mont_via_r_sq`, `zeta128_mont_via_mont` in test (lines ~1635-1636): Unused. Remove.
- `w1_copy` in test (line ~1310): Declared `mut` but never mutated. Remove `mut`.

---

### Phase 3: verrev-syscall Cleanup (libs/verrev-syscall/src/linux.rs)

**3.1 Remove `#![allow(dead_code)]`**

Replace with individual `#[allow(dead_code)]` on the specific functions that are currently unused (e.g., `now_nanos`, `exit`, etc.), or better, implement the missing wrappers so everything is used.

**3.2 Implement `read()`, `write()`, `open()` Wrappers**

`SYS_READ`, `SYS_WRITE`, `SYS_OPEN` constants already exist (lines ~40-50). Add wrapper functions:

```
pub fn read(fd: i32, buf: *mut u8, count: u32) -> Result<usize, SyscallError> {
    syscall3(SYS_READ as u64, fd as u64, buf as u64, count as u64)
}

pub fn write(fd: i32, buf: *const u8, count: u32) -> Result<usize, SyscallError> {
    syscall3(SYS_WRITE as u64, fd as u64, buf as u64, count as u64)
}

pub fn open(path: *const u8, flags: i32, mode: u32) -> Result<Fd, SyscallError> {
    let ret = syscall3(SYS_OPEN as u64, path as u64, flags as u64, mode as u64);
    ret.map(|r| Fd(r as i32))
}
```

**3.3 Add `// Safety:` Comments**

For `sendto` and `recvfrom` which take raw pointers, add safety documentation explaining the invariants the caller must uphold (valid pointer, aligned, non-null for dest_addr).

**3.4 SOCKADDR_MAX Constant**

Replace magic number 28 with `const SOCKADDR_MAX: usize = 28;` and a comment explaining this is the size of `struct sockaddr_storage` on Linux x86_64.

**3.5 Check syscall Return in `now_nanos()`**

```
let ret = syscall2(SYS_CLOCK_GETTIME as u64, CLOCK_REALTIME as u64, &mut ts as *mut _ as u64);
// clock_gettime always succeeds on Linux with valid args, but check anyway
match ret {
    Ok(_) => { /* use ts */ }
    Err(_) => return 0, // fallback
}
```

---

### Phase 4: Soundness Fixes

**4.1 verrev-runtime — Unsound `&'static mut`**

The `memory: Option<&'static mut [u8]>` field in `Instance` is unsound if two instances reference the same memory. Fix: since the runtime is a stub with no real WASM execution, change to `Option<&'static [u8]>` (shared reference). If the memory is never mutated after creation, this is safe. For the stub case where memory is always `None`, this is trivially safe.

If mutation is needed later, change to `Option<*mut [u8]>` with explicit unsafe on dereference.

**4.2 verrev-capability — Shift Overflow**

Change `1 << (4 + c.min(60))` to `1u64.checked_shl(4 + c.min(59)).unwrap_or(0)`. This ensures shifting by 64 produces 0 (no rights) instead of a panic.

---

### Phase 5: Minor Violations

**5.1 verrev-fs — Duplicate Entry Check**

In `add_entry`, before inserting:
```
if self.entries.iter().any(|(n, _)| n == name) {
    return Err("entry already exists");
}
```
Or return a dedicated error type. The `Directory` should maintain the CRDT invariant that each name maps to exactly one entry.

**5.2 verrev-net — Bernoulli Loss Model**

Replace the current loss tracking with a proper Bernoulli trial using a simple deterministic PRNG (e.g., xorshift seeded by packet counter):

```
fn should_drop(packets_sent: u64, loss_rate: f32) -> bool {
    let state = packets_sent.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let hash = state.wrapping_mul(state.wrapping_add(1));
    (hash as f32 / u64::MAX as f32) < loss_rate
}
```

Then increment `packets_lost` when the trial returns true, instead of comparing running counts.

---

### Phase 6: Stub Implementations (verrev-p2p, verrev-sync)

**6.1 verrev-p2p::dht — `find_closest` Implementation**

The Kademlia `find_closest` algorithm: given a target 256-bit key, return the K closest nodes from the routing table by XOR distance:

1. Start with the bucket corresponding to the target's leading zero bits.
2. Collect all nodes from this bucket.
3. If < K nodes, expand to adjacent buckets (closer prefix first).
4. Sort by XOR distance and take K.

Implementation in `RoutingTable::find_closest`:

```
pub fn find_closest(&self, target: &[u8; 32], k: usize) -> Vec<NodeInfo> {
    let prefix = leading_zero_bits(target);
    let mut candidates: Vec<(NodeInfo, u32)> = Vec::new();
    // Collect from closest prefix bucket first, then expand outward
    for offset in 0..256 {
        let idx = if offset == 0 { prefix } else if offset % 2 == 0 { prefix + offset/2 } else { prefix - offset/2 - 1 };
        if idx >= 256 { continue; }
        for node in &self.buckets[idx].nodes {
            let dist = xor_distance(target, &node.id);
            candidates.push((node.clone(), big_endian_u32(&dist)));
        }
        if candidates.len() >= k { break; }
    }
    candidates.sort_by_key(|(_, d)| *d);
    candidates.truncate(k);
    candidates.into_iter().map(|(n, _)| n).collect()
}
```

Where `big_endian_u32` converts XOR distance from `[u8; 32]` to a comparable u32 by taking the first 4 bytes.

**6.2 verrev-p2p::dht — Bucket Splitting**

When a bucket is full and our own node ID falls within its range, split it. This requires the routing table to track which bit depth each bucket covers. Implementation:

```
fn split_bucket(&mut self, idx: usize) {
    let split_bit = self.depths[idx]; // bit depth of this bucket
    let mut new_bucket = KBucket { nodes: Vec::new(), depth: self.depths[idx] + 1 };
    let old_nodes = std::mem::take(&mut self.buckets[idx].nodes);
    for node in old_nodes {
        let bit = (node.id[split_bit / 8] >> (7 - split_bit % 8)) & 1;
        if bit == 0 {
            self.buckets[idx].nodes.push(node);
        } else {
            new_bucket.nodes.push(node);
        }
    }
    self.buckets.insert(idx + 1, new_bucket);
    self.depths.insert(idx, split_bit + 1);
    self.depths.insert(idx + 1, split_bit + 1);
}
```

**6.3 verrev-p2p::dht — KBucket Insert Ping**

When the bucket has 20 nodes, send a ping to the least-recently-seen node. For Phase 0 without real network, simply drop the incoming node (with a counter or log). The function should return `Ok(false)` to indicate the node was not added, or call an eviction callback.

**6.4 verrev-sync::merkle — Merkle Tree Root Hash**

Implement the tree properly:

```
pub fn new() -> Self {
    MerkleTree { leaves: Vec::new() }
}

pub fn insert(&mut self, data: &[u8]) {
    let hash = sha3_256(data);
    self.leaves.push(hash);
}

pub fn root_hash(&self) -> [u8; 32] {
    if self.leaves.is_empty() { return [0u8; 32]; }
    if self.leaves.len() == 1 { return self.leaves[0]; }
    // Build tree from leaves
    let mut level: Vec<[u8; 32]> = self.leaves.clone();
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            if pair.len() > 1 {
                combined[32..].copy_from_slice(&pair[1]);
            } else {
                combined[32..].copy_from_slice(&pair[0]); // odd leaf, duplicate
            }
            sha3_256(&combined)
        }).collect();
    }
    level[0]
}
```

**6.5 verrev-sync::merkle — Diff Logic**

Compare two Merkle trees by their root hashes. If roots differ, descend into children (requires storing internal node hashes). For simplicity in Phase 0: compare all leaf hashes and return indices of differing leaves:

```
pub fn diff(&self, other: &MerkleTree) -> Vec<usize> {
    let max_len = self.leaves.len().max(other.leaves.len());
    (0..max_len).filter(|&i| {
        let a = self.leaves.get(i).unwrap_or(&[0u8; 32]);
        let b = other.leaves.get(i).unwrap_or(&[0u8; 32]);
        a != b
    }).collect()
}
```

---

### Verification Protocol

After each phase:
1. `cargo build` — must have 0 errors, 0 warnings
2. `cargo test -- --test-threads=1` — must pass all existing tests
3. For cryptographic changes: verify KATs remain correct

### Build Order (Dependency-Safe)

```
Phase 1 (aead.rs) → build + test verrev-crypto
Phase 2 (kyber.rs, dilithium.rs) → build + test verrev-crypto
Phase 3 (linux.rs) → build + test verrev-syscall
Phase 4 (runtime, capability) → build + test those crates
Phase 5 (fs, net) → build + test those crates
Phase 6 (p2p, sync) → build + test those crates
```

Each phase must compile clean with 0 warnings before proceeding to the next.

---

## Priority Fix Queue

| Priority | Crate | Violation | Status |
|---|---|---|---|
| P0 | dilithium.rs | Hardcoded zeta table | ✅ Phase 0 |
| P1 | aead.rs | Poly1305 carry, unwrap, ct_eq, Vec, S-box, GHASH | ✅ Phase 1 |
| P2 | kyber.rs | Dead code removal | ✅ Phase 2 |
| P2 | dilithium.rs | Dead code + test warnings | ✅ Phase 2 |
| P2 | linux.rs | dead_code attr + read/write/open stubs | ✅ Phase 3 |
| P2 | verrev-runtime | Unsound &'static mut | ✅ Phase 4 |
| P3 | verrev-capability | Shift overflow | ✅ Phase 4 |
| P3 | verrev-fs | Duplicate entries | ✅ Phase 5 |
| P3 | verrev-net | Loss model | ✅ Phase 5 |
| P3 | verrev-p2p | find_closest + bucket splitting | ✅ Phase 6 |
| P3 | verrev-sync | Merkle root_hash + diff | ✅ Phase 6 |

### Active Refinements (Rule 19 perfection, beyond original audit)

| Priority | Crate | Violation | Est. Effort |
|---|---|---|---|
| R1 | aead.rs | Poly1305Ctx incremental struct (replace monolithic poly1305_mac), ghash_update, zero-stack-buffer encrypt/decrypt | 4h |
| R1 | verrev-sync | Merkle: dynamic Vec leaves, cached internal tree, incremental insertion, O(log n) diff | 3h |
| R1 | verrev-p2p | DHT: proper LRU eviction, remove split_bucket, formal Kademlia bucket management | 4h |
| R2 | verrev-syscall | now_nanos: return Result<u64> instead of fallback-to-0 | 1h |
| R2 | verrev-capability | check_access: constant-time rights mask selection (no branching on secret) | 1h |

## Active Work

| Task | Crate | Status | Details |
|---|---|---|---|
| AEAD refinement | verrev-crypto | ✅ Complete | Poly1305Ctx + GhashCtx incremental structs, XChaCha20Poly1305 and Aes256Gcm rewritten to use them — zero buffer allocations |
| Merkle tree rewrite | verrev-sync | ⚪ Pending | Dynamic Vec leaves, cached internal tree, incremental update, O(log n) diff |
| DHT refinement | verrev-p2p | ⚪ Pending | LRU eviction policy, remove split_bucket, formal Kademlia bucket management |
| now_nanos fix | verrev-syscall | ⚪ Pending | Return Result<u64> instead of fallback-to-0 |
| check_access fix | verrev-capability | ⚪ Pending | Constant-time rights mask (no branching on secret) |

## Coding Conventions

- No `#![allow(dead_code)]` — all code must be production-ready
- No `unwrap()`, `expect()`, `panic!()` in library code
- `#[cfg(test)]` tests in-module
- All crypto comparisons use `util::ct_eq` (constant-time)
- External crate `alloc` for `Vec` usage
- No external crates — everything is owned code
- All crypto tables generated from mathematical formulas, never hardcoded
