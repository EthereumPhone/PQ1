/- Historical §33 P3 roadmap, superseded 2026-10-08.

   ForsLoop.lean proves termination and range of the extracted FORS decoders.
   ForsExtract.lean proves their exact arithmetic results (2026-06-12).
   ForsSpecBridge.lean now proves those results equal the verifier's vendored
   Util/Bits.lean definitions for every input digest, closing the decoder
   component tracked in #288. Both the HT index and all thirteen FORS fields
   are covered, including the forced-zero field without an acceptance premise.

   The byte-type adapter and its value/order theorem are explicit. Vendored
   definitions and parameters are drift-checked, and the four public bridge
   results are enrolled in the kernel-only closure manifest. The Rust-executed
   corpus checks translation on 262 inputs; it is not a soundness proof of
   Charon/Aeneas or an all-input theorem about compiled machine code.

   Decoder correspondence alone does not establish the full CWE-347 binding
   of every signing/recovery call, the SHA256 backend, or the complete Rust
   signer to the EasyCrypt game. Those limits remain in c10-port's
   RESEARCH-LIMITS.md. -/
