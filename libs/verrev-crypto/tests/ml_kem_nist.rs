//! ML-KEM-1024 conformance checks against official NIST ACVP fixtures.
//!
//! The fixtures are unmodified field values from the NIST ACVP-Server
//! repository; see `vectors/PROVENANCE.md` for the upstream commit, per-file
//! selections, and the verification that was performed against upstream.

use verrev_crypto::kyber;

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

#[test]
fn official_ml_kem_1024_key_generation_matches_nist() {
    let vector = Vector::new(include_str!("vectors/ml_kem_1024_keygen_tc51.rsp"));
    let d = vector.array("d");
    let z = vector.array("z");
    let (dk, ek) = kyber::keygen_deterministic(&d, &z);
    assert_eq!(ek.as_slice(), vector.bytes("ek"), "ACVP ML-KEM keyGen ek");
    assert_eq!(dk.as_slice(), vector.bytes("dk"), "ACVP ML-KEM keyGen dk");

    let encapsulation = Vector::new(include_str!(
        "vectors/ml_kem_1024_encapsulation_tc51.rsp"
    ));
    let ek = encapsulation.array("ek");
    let dk = encapsulation.array("dk");
    let msg = encapsulation.array("m");
    let (ciphertext, shared) = kyber::encaps_deterministic(&ek, &msg);
    assert_eq!(
        ciphertext.as_slice(),
        encapsulation.bytes("c"),
        "ACVP ML-KEM encapsulation ciphertext"
    );
    assert_eq!(
        shared.as_slice(),
        encapsulation.bytes("k"),
        "ACVP ML-KEM encapsulation shared secret"
    );
    assert_eq!(kyber::decaps_deterministic(&dk, &ciphertext), shared);
}

#[test]
fn official_valid_and_implicit_rejection_decapsulation() {
    for name in [
        "ml_kem_1024_decapsulation_tc97.rsp",
        "ml_kem_1024_modified_ciphertext_tc96.rsp",
    ] {
        let input = match name {
            "ml_kem_1024_decapsulation_tc97.rsp" => include_str!(
                "vectors/ml_kem_1024_decapsulation_tc97.rsp"
            ),
            _ => include_str!("vectors/ml_kem_1024_modified_ciphertext_tc96.rsp"),
        };
        let vector = Vector::new(input);
        let actual = kyber::decaps_deterministic(
            &vector.array("dk"),
            &vector.array("c"),
        );
        assert_eq!(actual.as_slice(), vector.bytes("k"), "ACVP case {name}");
    }
}

#[test]
fn ciphertext_mutation_changes_shared_secret_and_matches_rejection_formula() {
    let vector = Vector::new(include_str!(
        "vectors/ml_kem_1024_decapsulation_tc97.rsp"
    ));
    let dk = vector.array("dk");
    let mut ciphertext = vector.array("c");
    let valid = kyber::decaps_deterministic(&dk, &ciphertext);
    assert_eq!(valid.as_slice(), vector.bytes("k"));
    ciphertext[0] ^= 1;
    let rejected = kyber::decaps_deterministic(&dk, &ciphertext);
    assert_ne!(rejected, valid, "mutation must not silently validate");

    let modified = Vector::new(include_str!(
        "vectors/ml_kem_1024_modified_ciphertext_tc96.rsp"
    ));
    assert_eq!(
        kyber::decaps_deterministic(&modified.array("dk"), &modified.array("c"))
            .as_slice(),
        modified.bytes("k"),
        "official implicit-rejection result"
    );
}

#[test]
fn malformed_key_checks_reject_noncanonical_and_hash_mutations() {
    let vector = Vector::new(include_str!("vectors/ml_kem_1024_keygen_tc51.rsp"));
    let (mut dk, mut ek) = kyber::keygen_deterministic(
        &vector.array("d"),
        &vector.array("z"),
    );
    assert!(kyber::valid_encapsulation_key(&ek));
    assert!(kyber::valid_decapsulation_key(&dk));

    // A non-canonical 12-bit coefficient (q) must not pass the modulus check.
    ek[0] = 0x61;
    ek[1] = (ek[1] & 0xf0) | 0x0d;
    assert!(!kyber::valid_encapsulation_key(&ek));

    dk[1536 + 1568] ^= 1;
    assert!(!kyber::valid_decapsulation_key(&dk));
}
