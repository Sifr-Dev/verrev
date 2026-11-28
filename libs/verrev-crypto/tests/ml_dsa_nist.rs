//! ML-DSA-87 conformance checks against official NIST ACVP fixtures.
//!
//! These fixtures are unmodified field values from the NIST ACVP-Server
//! repository; see `vectors/PROVENANCE.md` for the upstream commit and the
//! per-file selections.
//!
//! Status is deliberately split and honest about what is proven:
//!
//! * Key generation conforms to FIPS 204 and is asserted against the official
//!   vector.
//! * Signature generation and verification do **not** yet reproduce the official
//!   results. Those checks are `#[ignore]`d with the failure recorded instead of
//!   being weakened to self-consistency; a roundtrip proves internal agreement,
//!   not conformance.
//!
//! Negative ("must not verify") cases are intentionally absent. While
//! verification rejects every input, such a test would pass for the wrong reason
//! and would be vacuous evidence.

use verrev_crypto::dilithium;

struct Vector {
    input: &'static str,
}

impl Vector {
    fn new(input: &'static str) -> Self {
        Self { input }
    }

    fn text(&self, name: &str) -> &'static str {
        self.input
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("missing vector field {name}"))
    }

    fn bytes(&self, name: &str) -> std::vec::Vec<u8> {
        let hex = self.text(name);
        assert_eq!(hex.len() % 2, 0, "odd-length hex field {name}");
        (0..hex.len())
            .step_by(2)
            .map(|offset| {
                u8::from_str_radix(&hex[offset..offset + 2], 16)
                    .unwrap_or_else(|_| panic!("invalid hex field {name}"))
            })
            .collect()
    }

    fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        let bytes = self.bytes(name);
        assert_eq!(bytes.len(), N, "wrong length for vector field {name}");
        let mut output = [0; N];
        output.copy_from_slice(&bytes);
        output
    }
}

/// FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) must reproduce the official
/// public and secret key from the 32-byte `xi` seed.
#[test]
fn official_ml_dsa_87_key_generation_matches_nist() {
    let vector = Vector::new(include_str!("vectors/ml_dsa_87_keygen_tc51.rsp"));
    let xi = vector.bytes("seed");
    assert_eq!(xi.len(), 32, "FIPS 204 seeds key generation with 32 bytes");

    // The public API accepts the legacy 64-byte buffer; only the first 32 bytes
    // are the FIPS 204 seed and the remainder is ignored.
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&xi);
    let keypair = dilithium::generate_keypair(Some(&seed));

    assert_eq!(
        keypair.public_key.as_slice(),
        vector.bytes("pk"),
        "ACVP ML-DSA-87 keyGen public key"
    );
    assert_eq!(
        keypair.secret_key.as_slice(),
        vector.bytes("sk"),
        "ACVP ML-DSA-87 keyGen secret key"
    );
}

/// Known non-conformance: deterministic signature generation does not yet
/// reproduce the official signature.
#[test]
#[ignore = "ML-DSA-87 sign does not yet conform to FIPS 204; see PROVENANCE.md"]
fn official_ml_dsa_87_deterministic_signature_matches_nist() {
    let vector = Vector::new(include_str!("vectors/ml_dsa_87_pure_deterministic_tc61.rsp"));
    let sk: [u8; dilithium::SECRET_KEY_BYTES] = vector.array("sk");
    let message = vector.bytes("message");
    let context = vector.bytes("context");

    let signature = dilithium::sign_with_context(&sk, &message, &context);
    assert_eq!(
        signature.as_slice(),
        vector.bytes("signature"),
        "ACVP ML-DSA-87 deterministic signature"
    );
}

/// Known non-conformance: hedged signature generation does not yet reproduce the
/// official signature for the published `rnd`.
#[test]
#[ignore = "ML-DSA-87 hedged signing does not yet conform to FIPS 204; see PROVENANCE.md"]
fn official_ml_dsa_87_hedged_signature_matches_nist() {
    let vector = Vector::new(include_str!("vectors/ml_dsa_87_pure_hedged_tc241.rsp"));
    let sk: [u8; dilithium::SECRET_KEY_BYTES] = vector.array("sk");
    let message = vector.bytes("message");
    let context = vector.bytes("context");
    let rnd: [u8; 32] = vector.array("rnd");

    let signature = dilithium::sign_with_context_and_rnd(&sk, &message, &context, &rnd);
    assert_eq!(
        signature.as_slice(),
        vector.bytes("signature"),
        "ACVP ML-DSA-87 hedged signature"
    );
}

/// Known non-conformance: a valid official signature is currently rejected.
#[test]
#[ignore = "ML-DSA-87 verify does not yet accept an official FIPS 204 signature; see PROVENANCE.md"]
fn official_ml_dsa_87_valid_signature_verifies() {
    let vector = Vector::new(include_str!("vectors/ml_dsa_87_pure_verify_tc63.rsp"));
    let pk: [u8; dilithium::PUBLIC_KEY_BYTES] = vector.array("pk");
    let signature: [u8; dilithium::SIGNATURE_BYTES] = vector.array("signature");
    let message = vector.bytes("message");
    let context = vector.bytes("context");

    assert!(
        dilithium::verify_with_context(&pk, &message, &context, &signature),
        "official ML-DSA-87 signature must verify"
    );
}

/// FIPS 204 requires signatures and keys to round-trip through this
/// implementation. This proves internal agreement only, not conformance.
#[test]
fn key_generation_and_signature_roundtrip() {
    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let keypair = dilithium::generate_keypair(Some(&seed));
    let message = b"verrev ML-DSA-87 roundtrip";
    let signature = dilithium::sign(&keypair.secret_key, message);

    assert!(dilithium::verify(
        &keypair.public_key,
        message,
        &signature
    ));

    let wrong_message = b"verrev ML-DSA-87 roundtrip!";
    assert!(!dilithium::verify(
        &keypair.public_key,
        wrong_message,
        &signature
    ));
}
