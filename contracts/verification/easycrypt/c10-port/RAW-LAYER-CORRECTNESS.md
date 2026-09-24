# Actual hypertree-layer correctness

ActualLayerConstruction executes a separate RawKeygen.root call, actual
RawLayer.sign, and a later RawLayer.recover call when signing succeeds. With
probability one, a successful signature recovers exactly that earlier keygen
root. Bounded WOTS count failure remains an explicit None result.

The proof connects every actual Merkle catalog leaf to the WOTS chains and
leaf-compression entry produced by actual key generation. The builder's
returned authentication array therefore belongs to that WOTS leaf. Exact
observer projections retain the internally computed builder root while
preserving actual signatures and all oracle effects.

A separate root-identity argument proves that sound catalogs sharing the
same retained WOTS leaves agree at each common node. A complete recorded
catalog supplies a persistent root witness. Rebuilding later, including for
a different valid target, yields the same root as the earlier keygen call.
This equality is proved rather than inferred from internal reconstruction.

Accepted signatures retain their WOTS count/chain witness and Merkle path
through the recovery performed during signing. A separate recovery replays
that opening, and later table extensions preserve it. Valid target indices
0 through 511 remain explicit. Zero nodes are allowed.

The certificate enrolls all twenty layer modules and eleven semantic/scope
controls. Both proof drivers and the full cold gate check the proof bodies;
the bounded review and merge receipt bind that evidence to the candidate.

The [structured signer](RAW-SIGNER-CORRECTNESS.md) and
[byte signer](RAW-BYTE-SIGNER-CORRECTNESS.md) supply honest full composition.
Accumulated adaptive opening coverage and numerical end-to-end forgery bounds
remain open under #100/#295. This classical
independent-table manual model is not Rust extraction, a concrete SHA-256
proof, QROM or production authority. #509 remains owner-triggered and deferred.
