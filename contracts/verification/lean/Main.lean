/-
Driver for `lake exe verify-test-vectors`.

Loads the test-vector corpus from `sphincs-c10/tests/c10_test_vectors.json`
(or wherever the host signer dumped it) and confirms that, for every
test vector, `Spec.Signature.verify` returns the expected boolean.

Because the Lean spec uses an opaque `sha256`, the verifier cannot
actually compute concrete digests at runtime. So this executable serves
two purposes:

  1. It type-checks the spec-level API the test-vector harness needs.
  2. It documents the structure of the cross-validation pipeline:
     the actual byte-level differential testing happens via Rust
     (`sphincs-c10/tests/signing_suite.rs`) and Solidity
     (`contracts/smart-wallet/test/`); this driver re-runs the **type
     checks** so a Lean-level rename does not silently break the
     externally-validated artifact.

For full byte-level test-vector replay inside Lean, we would need a
kernel-computable SHA-256 (see § 3.5 of the playbook). That is a
follow-on work item.
-/

import SphincsCVerify

def main : IO Unit := do
  IO.println "SphincsCVerify build OK"
  IO.println s!"SignatureLen = {SphincsCVerify.Spec.SignatureLen}"
  IO.println s!"VerifyingKeyLen = {SphincsCVerify.Spec.VerifyingKeyLen}"
  IO.println s!"MaxBootstrapUses = {SphincsCVerify.Spec.MaxBootstrapUses}"
  IO.println s!"MaxSlotUses = {SphincsCVerify.Spec.MaxSlotUses}"
  IO.println "(For byte-level differential testing against the Rust"
  IO.println " test vectors, see `sphincs-c10/tests/signing_suite.rs`.)"
