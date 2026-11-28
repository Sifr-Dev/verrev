# NIST ACVP fixture provenance

These fixtures contain unmodified field values extracted from the official NIST
ACVP-Server generated test-vector repository. They are not implementation output.

Upstream commit: 975de31eb83d87039ec88934fdc47d8c312b892d
Upstream tree: https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
Retrieved: 2026-11-27 (UTC) via HTTPS from raw.githubusercontent.com.
Specification: FIPS 203 (https://doi.org/10.6028/NIST.FIPS.203), final 2024-08-13.
Specification: FIPS 204 (https://doi.org/10.6028/NIST.FIPS.204), final 2024-08-13.

## Verification performed

Every source JSON hash below was recomputed from the upstream commit with
`sha256sum`, and every `name=value` field in every `.rsp` file was compared
programmatically against the corresponding upstream `tcId`/`tgId`/`vsId` entry.
All 11 fixtures matched their upstream source. The two NIST specification PDFs
were downloaded from `nvlpubs.nist.gov` and hashed locally.

Specification PDFs (SHA-256, `nvlpubs.nist.gov/nistpubs/FIPS/`):
- NIST.FIPS.203.pdf: fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac
- NIST.FIPS.204.pdf: 1d4f2baae9472233393960a8e64c1637bbf5061454e72dd806d2f1841b24cd68

Upstream source file hashes (SHA-256):
- ML-KEM-keyGen-FIPS203/internalProjection.json: d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b
- ML-KEM-encapDecap-FIPS203/internalProjection.json: a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f
- ML-DSA-keyGen-FIPS204/internalProjection.json: e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf
- ML-DSA-sigGen-FIPS204/internalProjection.json: 72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22
- ML-DSA-sigVer-FIPS204/internalProjection.json: 47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437

## Selections

- ML-KEM-keyGen-FIPS203 (d7a62a2c...):
  ml_kem_1024_keygen_tc51.rsp: vsId=42, tgId=3, tcId=51, parameterSet=ML-KEM-1024, testType=AFT
- ML-KEM-encapDecap-FIPS203 (a556952c...):
  ml_kem_1024_encapsulation_tc51.rsp: vsId=42, tgId=3, tcId=51, function=encapsulation, testType=AFT
- ML-KEM-encapDecap-FIPS203 (a556952c...):
  ml_kem_1024_decapsulation_tc97.rsp: vsId=42, tgId=6, tcId=97, function=decapsulation, testType=VAL
- ML-KEM-encapDecap-FIPS203 (a556952c...):
  ml_kem_1024_modified_ciphertext_tc96.rsp: vsId=42, tgId=6, tcId=96, function=decapsulation, testType=VAL
- ML-DSA-keyGen-FIPS204 (e67ee654...):
  ml_dsa_87_keygen_tc51.rsp: vsId=42, tgId=3, tcId=51, parameterSet=ML-DSA-87, testType=AFT
- ML-DSA-sigGen-FIPS204 (72dcaf5f...):
  ml_dsa_87_pure_deterministic_tc61.rsp: vsId=42, tgId=5, tcId=61, deterministic=true, signatureInterface=external, preHash=pure
- ML-DSA-sigGen-FIPS204 (72dcaf5f...):
  ml_dsa_87_pure_hedged_tc241.rsp: vsId=42, tgId=17, tcId=241, deterministic=false, signatureInterface=external, preHash=pure
- ML-DSA-sigVer-FIPS204 (47cdd631...):
  ml_dsa_87_pure_verify_tc63.rsp: vsId=42, tgId=5, tcId=63, signatureInterface=external, preHash=pure
- ML-DSA-sigVer-FIPS204 (47cdd631...):
  ml_dsa_87_modified_message_tc61.rsp: vsId=42, tgId=5, tcId=61, signatureInterface=external, preHash=pure
- ML-DSA-sigVer-FIPS204 (47cdd631...):
  ml_dsa_87_internal_verify_tc168.rsp: vsId=42, tgId=12, tcId=168, signatureInterface=internal, preHash=none
- ML-DSA-sigVer-FIPS204 (47cdd631...):
  ml_dsa_87_modified_hint_tc166.rsp: vsId=42, tgId=12, tcId=166, signatureInterface=internal, preHash=none

## Conformance status at this commit

ML-KEM-1024 (`tests/ml_kem_nist.rs`) passes all four checks against the official
fixtures: key generation, deterministic encapsulation, valid decapsulation, and
implicit-rejection decapsulation of a modified ciphertext.

ML-DSA-87 is not yet conformant:

- Key generation matches the official vector exactly (`official_ml_dsa_87_key_generation_matches_nist`).
- Deterministic signature generation does not reproduce the official signature.
  The check is `#[ignore]`d with the failure recorded rather than weakened.
- Official valid signatures are currently rejected by `verify`. The positive
  check is `#[ignore]`d for the same reason.

Because verification rejects every input today, negative ("must not verify")
tests would pass for the wrong reason and are deliberately not included; adding
them now would be vacuous evidence.

Root causes identified while adding the fixtures, with independent derivations
recorded in the review notes:

1. Key generation hashed a zero-padded 64-byte buffer instead of FIPS 204's
   32-byte `xi || k || l` input, and derived a 96-byte expansion instead of 128.
2. `tr` was 32 bytes and placed after the secret vectors; FIPS 204 uses a
   64-byte `tr = H(pk, 64)` stored immediately after `rho || K`.
3. `ExpandA` absorbed a single little-endian `u16` nonce instead of
   `rho || column || row` as separate bytes.
4. `ExpandS` absorbed a one-byte nonce instead of a two-byte little-endian one.

Items 1-4 are fixed. Signature generation and verification still diverge from
FIPS 204; the remaining difference has not yet been isolated.

## License and attribution

NIST-developed software and data are supplied as a public service. The
ACVP-Server README permits use, copying, distribution, and modification,
requires preservation of its notice and acknowledgment of NIST, and provides
the material AS IS without warranty. NIST employee work is not subject to
copyright protection in the United States. The complete notice is reproduced
in NIST-LICENSE.txt. Fixture extraction changed only representation: selected
JSON fields were written as `name=value` hexadecimal/text lines; no field value
or expected result was changed.

## Unused fixtures and why

Three captured fixtures are intentionally not wired into a test at this commit:

- `ml_dsa_87_modified_message_tc61.rsp`
- `ml_dsa_87_modified_hint_tc166.rsp`
- `ml_dsa_87_internal_verify_tc168.rsp`

The first two are negative sigVer cases ("must not verify"). While
`dilithium::verify` rejects every input, asserting rejection would pass for the
wrong reason and prove nothing, so they are not used. The third exercises the
FIPS 204 *internal* interface (`signatureInterface=internal`), which operates on
a precomputed `mu` with no context; the crate exposes no internal-interface entry
point, so it cannot be exercised without first adding that API.

They are retained so the eventual conformance work does not need to re-extract
them. They must not be cited as passing evidence.
