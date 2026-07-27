# Verrev Engineering Rules

## 1. No Compromises
Every line is final architecture. There is no "works for now," no "we'll fix it later," no "good enough for phase 0." If it's not production-ready, it doesn't get written.

## 2. Build Incrementally, Never Refactor
Add to what exists. Never change existing code once written. Every addition is final — the same syscall interface designed today is what the microkernel exposes in Phase 4. The same capability model designed today is what the kernel enforces. No rewrites. No refactors.

## 3. Production-Ready by Default
Every function, every module, every crate is production-quality before it is committed. Memory-safe. Constant-time where applicable. Panic-free in production paths. Formatted to Verrev coding standards.

## 4. Zero External Dependencies
No libc. No OpenSSL. No wasmtime. No Tokio. No Linux kernel interfaces beyond raw syscalls. Every line is owned code. Rust compiler + LLVM are the only external dependencies.

## 5. `#![no_std]` from Day One
Every library compiles without the Rust standard library. On Linux (Phase 0), a thin syscall shim in `verrev-syscall` bridges to the kernel. That shim is replaced by direct kernel syscalls in Phase 4 — the interface does not change.

## 6. Architecture-First, Prototype-Never
Design for the final architecture on day one. The dependency chain is fixed:
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
Each layer depends only on layers below it. No circular dependencies. No layer skips.

## 7. Post-Quantum by Default
There is no "classic mode." Kyber-1024 (ML-KEM-1024) for KEM. Dilithium-5 (ML-DSA-87) for signatures. These are the only primitives. No RSA, no ECDSA, no X25519, no hybrid fallback anywhere in the stack.

## 8. Capability-Secure from Day One
Every operation — memory access, network bind, storage read/write, identity operation, compute execution, UI event — is gated by a capability token. No ambient authority. Capabilities support delegation, attenuation, and revocation.

## 9. Identity is the Root
Every peer, every service, every capability is bound to a Verrev identity: SHA3-256(Dilithium-5 public key). There is no notion of "anonymous" or "unauthenticated" in the protocol.

## 10. Content-Addressing for Everything
Files, messages, app bundles, state, credentials — all addressed by SHA3-256 hash. No sequential IDs, no paths, no locations. SHA-3 is provided by `verrev-hash`, the single hash primitive used by every layer.

## 11. CRDTs Everywhere
State is always mergeable. No locks. No conflicts. No central authority. Every data structure converges without coordination.

## 12. Constant-Time by Default
Every crypto primitive is verified constant-time. Every comparison of secret data (`ct_eq`, `ct_select`, `ct_swap`) uses the constant-time utilities. No branching on secrets.

## 13. Deterministic Builds
The same commit always produces the same binary. No build-time randomness leaks into the binary. No build-dependency on network access.

## 14. Test from Day One
Every crypto primitive has Known-Answer Tests (KATs) against NIST vectors. Every protocol has chaos tests. Every CRDT has convergence tests. No code is committed without tests.

## 15. Protocol Upgrades via Voting
Protocol evolution is governed by identity-weighted voting. Any identity can propose an upgrade. Approval requires ≥67% of voting identities with ≥10% quorum. Votes are CRDT-based — no central tally authority.

## 16. Offline-First, Mesh-Synced
Every component works without network. Local state is authoritative. Sync across peers is eventual, via Merkle-tree delta reconciliation. The mesh provides store-and-forward delivery for offline recipients.

## 17. Distributed by Default
Every service is distributed. No single point of failure. No central coordinator. Storage is erasure-coded across the mesh. Compute is replicated and verified. Names are resolved via DHT. All trust is rooted in identity and capabilities.

## 18. Violations Are Blockers
Any code that violates these rules must be rewritten before the next commit. There is no backlog of "tech debt" — tech debt is not permitted to exist.

## 19. Absolute Perfection, Not Pragmatism
"Good enough" does not exist. "Works for now" does not exist. "We'll fix it later" does not exist. Every function must be the absolute best implementation you are capable of — the fastest algorithm, the most memory-efficient data structure, the most mathematically rigorous reduction, the tightest constant-time execution. If implementing the correct algorithm takes a lifetime, you start it now and work it crate by crate, function by function, until it is done. Pragmatism is the enemy of correctness. There is no deadline, only standard. Every line you write must be the line you would defend in a formal verification proof. If you catch yourself thinking "this is simpler and probably good enough," stop — that thought is a violation. Rewrite that thought, then rewrite the code.

## 20. No Rushing Without Understanding
Time is irrelevant. Verbosity is not a concern. Speed of delivery is not a metric. The only metric is correctness and absolute perfection. If you catch yourself thinking "this is getting long but let me just do it," or "this should be straightforward so I can rush," or "let me wrap this up quickly so I can move on" — stop. That thought is a violation of Rule 19. You must understand the problem completely, verify every mathematical claim, prove every algorithm correct, and only then write the implementation. There is no deadline, no schedule, no urgency — only the standard. If it takes a thousand pages of analysis, write a thousand pages. If it takes a year of formal verification, spend the year. The codebase will not be complete until every line meets Rule 19 — and not one second before.
