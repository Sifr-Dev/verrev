---
name: verrev-rules
description: >-
  ALWAYS load. Engineering rules for the Verrev project. No compromises,
  no refactors, production-ready from day one. Build incrementally, never
  rewrite. Zero external dependencies. Post-quantum crypto only.
  Capability-secure. CRDTs everywhere. Constant-time by default.
  Deterministic builds. Test from day one.
---

# Verrev Engineering Rules

These rules are loaded before every prompt. Follow them absolutely.

## 1. No Compromises
Every line is final architecture. There is no "works for now," no "we'll fix it later," no "good enough for phase 0." If it's not production-ready, it doesn't get written.

## 2. Build Incrementally, Never Refactor
Add to what exists. Never change existing code once written. Every addition is final — the same syscall interface designed today is what the microkernel exposes in Phase 2. The same capability model designed today is what the kernel enforces in Phase 4. No rewrites. No refactors.

## 3. Production-Ready by Default
Every function, every module, every crate is production-quality before it is committed. Memory-safe. Constant-time where applicable. Panic-free in production paths. Formatted to Verrev coding standards.

## 4. Zero External Dependencies
No libc. No OpenSSL. No wasmtime. No Tokio. No Linux kernel interfaces beyond raw syscalls. Every line is owned code. Rust compiler + LLVM are the only external dependencies.

## 5. `#![no_std]` from Day One
Every library compiles without the Rust standard library. On Linux (Phase 0), a thin syscall shim in `verrev-syscall` bridges to the kernel. That shim is replaced by direct kernel syscalls in Phase 2 — the interface does not change.

## 6. Architecture-First, Prototype-Never
Design for the final architecture on day one. The dependency chain is fixed:
```
verrev-syscall → verrev-crypto → verrev-identity → verrev-transport
→ verrev-p2p → verrev-sync → verrev-store → verrev-runtime
→ verrev-capability → verrev-ui → apps
```
Each layer depends only on layers below it. No circular dependencies. No layer skips.

## 7. Post-Quantum by Default
There is no "classic mode." Kyber-1024 for KEM. Dilithium-7 for signatures. These are the only primitives. No RSA, no ECDSA, no X25519 anywhere in the stack.

## 8. Capability-Secure from Day One
Even Phase 0's WASM sandbox uses capability tokens, not UNIX permissions. Every access check goes through the capability layer. No ambient authority.

## 9. Identity is the Root
Every peer, every service, every capability is bound to a Verrev identity (Dilithium public key → 32-byte hash). There is no notion of "anonymous" or "unauthenticated" in the protocol.

## 10. Content-Addressing for Everything
Files, messages, app bundles, state — all addressed by SHA-3-256 hash. No sequential IDs, no paths, no locations.

## 11. CRDTs Everywhere
State is always mergeable. No locks. No conflicts. No central authority. Every data structure converges without coordination.

## 12. Constant-Time by Default
Every crypto primitive is verified constant-time. Every comparison of secret data (`ct_eq`, `ct_select`, `ct_swap`) uses the constant-time utilities. No branching on secrets.

## 13. Deterministic Builds
The same commit always produces the same binary. No build-time randomness leaks into the binary. No build-dependency on network access.

## 14. Test from Day One
Every crypto primitive has Known-Answer Tests (KATs) against NIST vectors. Every protocol has chaos tests. Every CRDT has convergence tests. No code is committed without tests.

## 15. Violations Are Blockers
Any code that violates these rules must be rewritten before the next commit. There is no backlog of "tech debt" — tech debt is not permitted to exist.

## Reference
- Full rules document: `/home/mohamed/programming/verrev/rules.md`
- Technical plan: `/home/mohamed/programming/verrev/PLAN.md`
- Project root: `/home/mohamed/programming/verrev/`
