# Actual WOTS component correctness

The classical independent-table model now has a complete component theorem
for actual RawKeygen.leaf, RawWots.sign and RawWots.recover. ActualWotsConstruction
calls those real model procedures in sequence. With probability one, either
bounded count search returns None and recovery is not called, or the signature
recovers exactly the leaf produced by key generation.

The proof supplies the witness rather than assuming a keygen/signature
relation. The actual keygen loop records all 43 private starts and seven-step
public chains. Exact refactorings preserve return values and every oracle
effect. Prefix/suffix replay follows those retained raw hash inputs.

The concrete software shuffle is proved to preserve a permutation of the
requested index range. This covers the zero-seed identity branch, byte bounds,
its multiply-high selection, and both list updates. It makes no uniform-shuffle
claim. The actual signing loop fills every index with its accepted digit's
reference-chain prefix. A successful count carries its exact input and accepted
digest; it is not replaced with an independent sample or success assumption.

Recovery consumes that same count entry and the retained suffixes. The final
43-chain compression is the recorded keygen leaf input. A separate theorem
retains the invalid-sum behavior: recovery returns the 16-byte zero sentinel.
Zero reference nodes remain allowed throughout. Losslessness supplies the
probability-one statement; bounded signing failure remains explicit.

The certificate enrolls all 32 WOTS modules and twelve semantic/scope
controls. Each proof body is checked through direct and default-CLI drivers.
The required full cold replay and bounded review bind the merge receipt to
the candidate identity.

The [forest component](RAW-FOREST-CORRECTNESS.md) separately supplies actual
forest composition. The [complete honest-signing theorem](RAW-BYTE-SIGNER-CORRECTNESS.md)
now supplies hypertree/full correctness. Adaptive opening coverage, component
forgery reduction and numerical end-to-end bounds remain open under #100/#295.
The [public collision](RAW-PUBLIC-NODE-COLLISIONS.md) and
[zero-sentinel](RAW-ZERO-NODE-CHARGE.md) charges have separate checked statements. There is no new project axiom, admit or clone assumption. The
independent-table intermediate statements are not transferred literally to
physical Rust by the whole-game prefix hop. No extraction, concrete SHA-256,
QROM, deployed 96-bit security or production authority is claimed.
