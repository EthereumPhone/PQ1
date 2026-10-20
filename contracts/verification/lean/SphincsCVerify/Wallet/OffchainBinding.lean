/-
Off-chain / on-chain signing-domain separation (Gap-3, faithfulness audit
2026-06-14).

The on-chain UserOp path verifies a bare C10 signature over
`sphincsDigest op` — a SHA-256 digest. The off-chain EIP-1271 path verifies
over a value the FIRMWARE (never the companion) nests through Solady's
`replaySafeHash`: a nested EIP-712 (PersonalSign) wrap whose outermost
operation is `keccak256` (see `aa/src/eip1271.rs` and the on-chain `ERC1271`
base, which applies the nesting in the public `isValidSignature` before the
internal `_erc1271IsValidSignatureNowCalldata` hook this project models in
`Wallet/IsValidSignature.lean`). Since the 2026-10-20 audit freeze the wallet
keeps ONLY Solady's nested workflow (`_erc1271IsValidSignature` override):
Solady's two raw-hash workflows — the MulticallerWithSigner "safe caller" and
the `tx.gasprice == 0` RPC path, which checked the bare hash — are gone
(GitHub #691), so every accepted off-chain signature, on both the bytes32 and
the legacy `isValidSignature(bytes,bytes)` entry, is over the nested value.

The security invariant — the RAW32 UserOp-forgery-oracle defense, fixed
2026-06-11 — is that an off-chain-signed value can never coincide with any
UserOp's `sphincsDigest`. If it could, a malicious companion could request an
off-chain signature over `raw32 = sphincsDigest(drainOp)` and reuse the
resulting C10 signature as a valid Type-2 UserOp signature to drain the wallet.

This file models the nesting and proves the disjointness, reducing it to a
single cited cross-hash assumption: a keccak-256 image equals a SHA-256 image
only if a hash hardness assumption is broken (`keccak_sha256_cross_separation`,
stated in the same consistent `… ∨ BreaksHash` reduction style as
`sha256_collision_resistance`, never concluding `False`).
-/

import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.IsValidSignature
import SphincsCVerify.Crypto.Assumptions

namespace SphincsCVerify.Wallet.OffchainBinding

open SphincsCVerify.Spec
open SphincsCVerify.Crypto
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.ValidateUserOp

/-- Keccak-256 over a `ByteSeg` list — the EVM-mandated hash. Modeled as an
    uninterpreted total function (like the §33 extracted `keccak256_pure`); the
    nesting STRUCTURE, not keccak's internals, is what this file reasons about.
    `opaque` (Classical.choice-backed), so it adds no named axiom to any
    `#print axioms` closure. -/
opaque keccak256 : List ByteSeg → ByteVec 32

/-- **Cross-hash domain separation (cited assumption).** A keccak-256 image
    equals a SHA-256 image only if a hash hardness assumption is broken.
    keccak-256 and SHA-256 are independent functions; exhibiting `x, y` with
    `keccak256 x = sha256 y` is a cross-hash collision — the `BreaksHash`
    witness. Stated in the same consistent reduction shape as
    `sha256_collision_resistance`: it never concludes `False`, and `BreaksHash`
    must NEVER be assumed false (that would re-introduce an inconsistency).

    **OC2 — QUANTITATIVE floor (partial / cited-tcb).** This axiom is the
    QUALITATIVE reduction; its `BreaksHash` disjunct is NOT free. The explicit
    search-game bound lives in `Crypto/Quantitative.lean` (§ Cross-function
    separation): both images share the 256-bit `ByteVec 32` codomain, so the floor
    is NOT automatically `2⁻²⁵⁶` — it is `256 − 2·qBits` (both-messages-vary claw /
    birthday, `crossClawBits`) or `256 − qBits` (fixed-target preimage,
    `crossPreimageBits`). The RAW32 attacker varies BOTH the off-chain `rawHash`
    and the draining UserOp, so the OPERATIVE floor is the claw: **128 bits at
    `2⁶⁴` work (`crossClaw_at_2pow64`) — C10's Cat-1 design level**, i.e. the same
    birthday strength the whole wallet lives at. The axiom stays `cited-tcb`: the
    quantitative layer bounds the feasibility of the disjunct, it does not
    discharge it. (Replaces the earlier "structurally impossible / disjoint"
    framing, which conflated the two regimes and implied a `2⁻²⁵⁶` that only holds
    for a fixed target.) -/
axiom keccak_sha256_cross_separation
    (ksegs ssegs : List ByteSeg) :
    keccak256 ksegs ≠ sha256 ssegs ∨ BreaksHash

/-- Solady's `replaySafeHash` — the nested-EIP-712 (PersonalSign) wrap the
    firmware applies to every off-chain hash before C10-signing. Mirrors
    `aa/src/eip1271.rs::replay_safe_hash` and the on-chain `ERC1271` base:

      structHash = keccak256(PERSONAL_SIGN_TYPEHASH ‖ rawHash)
      final      = keccak256("\x19\x01" ‖ domainSep ‖ structHash)

    The EIP-712 prefix and domain separator are parameters (the domain depends
    on chainId + verifying contract). The load-bearing structural fact, and all
    the disjointness proof needs, is that the OUTERMOST operation is
    `keccak256`. -/
noncomputable def replaySafeHash
    (rawHash personalSignTypeHash domainSep : ByteVec 32)
    (eip712Prefix : ByteSeg) : ByteVec 32 :=
  let structHash := keccak256 [ByteSeg.ofByteVec personalSignTypeHash,
                               ByteSeg.ofByteVec rawHash]
  keccak256 [eip712Prefix, ByteSeg.ofByteVec domainSep, ByteSeg.ofByteVec structHash]

/-- The off-chain EIP-1271 entry point WITH the firmware's nesting made
    explicit: the raw dapp hash is `replaySafeHash`-nested before the inner C10
    verification. (`IsValidSignature.erc1271IsValidSignature` models the inner
    hook, which receives the already-nested hash; this composes the nesting the
    Solady `ERC1271` base performs in the public `isValidSignature`.)

    NOTE — this is a NON-CONSUMED reference model. It documents the nesting
    composition for the reader; the disjointness theorem below does not call it
    (it reasons about `replaySafeHash`'s outermost keccak directly). The bytecode
    binding of the EIP-1271 dispatch is carried separately by
    `test/halmos/HalmosIsValidSignature.t.sol` (G8), not by this model. -/
noncomputable def erc1271IsValidSignatureNested
    (s : Storage)
    (rawHash personalSignTypeHash domainSep : ByteVec 32)
    (eip712Prefix : ByteSeg)
    (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Bool :=
  IsValidSignature.erc1271IsValidSignature s
    (replaySafeHash rawHash personalSignTypeHash domainSep eip712Prefix)
    signature verify_fn

/-- The legacy EIP-1271 entry `isValidSignature(bytes,bytes)` (selector
    `0x20c13b0b`; Safe v1.3.0 / v1.4.1 call it on a contract owner, GitHub
    #995). The deployed wallet hashes `data` with keccak-256 and runs the same
    nested check as the bytes32 entry on that hash. The hash is a parameter
    (`dataHash = keccak256(data)`), so the legacy entry is, by definition, the
    nested entry at `dataHash`; `test/halmos/HalmosIsValidSignature.t.sol`
    proves the bytecode agrees. -/
noncomputable def erc1271IsValidSignatureLegacy
    (s : Storage)
    (dataHash personalSignTypeHash domainSep : ByteVec 32)
    (eip712Prefix : ByteSeg)
    (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Bool :=
  erc1271IsValidSignatureNested s dataHash personalSignTypeHash domainSep eip712Prefix
    signature verify_fn

/-- The legacy entry, like every off-chain path, never accepts the
    bootstrap key (I-6 / G8). -/
theorem erc1271IsValidSignatureLegacy_rejects_bootstrap
    (s : Storage)
    (dataHash personalSignTypeHash domainSep : ByteVec 32)
    (eip712Prefix : ByteSeg)
    (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig signature = some d)
    (h0 : d.ownerIndex = 0) :
    erc1271IsValidSignatureLegacy s dataHash personalSignTypeHash domainSep eip712Prefix
      signature verify_fn = false :=
  IsValidSignature.erc1271IsValidSignature_rejects_bootstrap s _ signature verify_fn d hdec h0

/-- **Gap-3 / RAW32-oracle defense — message-image disjointness.** What this
    theorem proves: the value the off-chain path signs (`replaySafeHash …`, a
    keccak-256 image) is never equal to any UserOp's `sphincsDigest` (a SHA-256
    image) — unless a SHA-256 hardness assumption is broken (`∨ BreaksHash`).
    Disjointness reduces to the cited `keccak_sha256_cross_separation` axiom.

    **Honest scope of the RAW32-oracle claim.** The inference from this
    message-disjointness to "an off-chain C10 signature is therefore never a
    valid UserOp signature" is the EUF-CMA property (A5): a signature binds its
    message, so a signature over the (distinct) off-chain message is not a
    signature over any UserOp digest absent a forgery. That message⇒signature
    step is carried by the cited A5 reduction and is NOT separately mechanized in
    this corollary — it is exactly the conjunct-2 tie-in that
    `userop_acceptance_implies_signed_or_break` instantiates for the on-chain
    path. So this theorem alone establishes message-disjointness, not
    signature-non-validity. -/
theorem offchain_nested_disjoint_from_userop_digest
    (rawHash personalSignTypeHash domainSep : ByteVec 32) (eip712Prefix : ByteSeg)
    (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat) :
    replaySafeHash rawHash personalSignTypeHash domainSep eip712Prefix
      ≠ sphincsDigest op entryPoint chainId ∨ BreaksHash := by
  unfold replaySafeHash sphincsDigest sha256_concat
  exact keccak_sha256_cross_separation _ _

end SphincsCVerify.Wallet.OffchainBinding
