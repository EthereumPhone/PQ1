/- verify_signs completeness — the `consistent` capstone (increment 3/3).

   `honest_consistent : WellFormed sk → consistent sk` — the reference signer's
   output is accepted by the verifier, for any well-formed key. Composes the
   whole stack: the grind postconditions (`Spec/SignerPost.lean`), the FORS-pk
   and hypertree round-trips (`Verifier/*Roundtrip.lean`), and the completed
   reference signer (`Spec/Signer.lean`). `consistent`/`verify_signs` are
   unchanged — this is the new top-level theorem discharging `consistent`'s
   honestly-keygen'd content.

   ## SCOPE / TRUST BASE (read before citing this result)

   This is a *completeness* (usability) guarantee, NOT a safety one: it is not in
   `theft_free`'s dependency closure. It says "the spec signer round-trips with
   the spec verifier". Read as "the firmware's signatures are accepted on-chain"
   only via TWO bridges:
     (a) spec-`verify` = the on-chain verifier — REAL, anchored by A3.1
         (`execC10Asm`=spec) + the independent-KAT leg.
     (b) spec-`Signer.sign` = the firmware signer — **ASSUMED**. `Spec.Signer.sign`
         is a hand-written, `noncomputable`, un-anchored model. It was completed
         (commit b75e5a47) by reverse-engineering it to emit the verifier's own
         reconstruction shapes (`mtAuthPath`/`forsMtAuthPath`/`keygenPk`-chains),
         so the round-trip hypotheses discharge by construction. The proof
         therefore CANNOT detect an unfaithful-but-self-consistent `sign` (one
         that mis-derives an ADRS/hash in a way the verifier reconstruction also
         mis-uses). Bridge (b) is a trust-base item.
   Follow-up to strengthen (b): cross-check `Spec.Signer.sign` against an
   independent anchor — the Rust/Python KAT oracle or `serialise`/`deserialise`
   + the deployed verifier path — rather than leaving it verifier-derived. -/
import SphincsCVerify.Spec.SignerPost
import SphincsCVerify.Spec.Theorems
import SphincsCVerify.Verifier.ForsRoundtrip
import SphincsCVerify.Verifier.HypertreeRoundtrip

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify SphincsCVerify.Spec SphincsCVerify.Spec.Signer SphincsCVerify.Util

local instance : Inhabited (ByteVec 16) := ⟨ByteVec.zero 16⟩

/-- `Array.ofFn` indexing by `getD` at an in-bounds index. -/
theorem ofFn_getD {α} {n : Nat} (f : Fin n → α) (i : Nat) (d : α) (h : i < n) :
    (Array.ofFn f).getD i d = f ⟨i, h⟩ := by
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn]; simp [h]

/-- `Array.ofFn` indexing by `getElem!` at an in-bounds index. -/
theorem ofFn_getElem! {α} [Inhabited α] {n : Nat} (f : Fin n → α) (i : Nat) (h : i < n) :
    (Array.ofFn f)[i]! = f ⟨i, h⟩ := by
  rw [Array.getElem!_eq_getD]; exact ofFn_getD f i default h

/-- A value AND a low-bit mask `(1 <<< k) - 1` is below `2^k`. -/
theorem and_mask_lt (a k : Nat) : a &&& ((1 <<< k) - 1) < 2 ^ k := by
  have h1 : (1 <<< k) - 1 = 2 ^ k - 1 := by rw [Nat.one_shiftLeft]
  rw [h1]
  have hle : a &&& (2 ^ k - 1) ≤ 2 ^ k - 1 := Nat.and_le_right
  have hp : 0 < 2 ^ k := Nat.two_pow_pos k
  omega

/-- **Top hypertree layer's tree index is always 0.** `extractHtIndex` is an
    `H`-bit value and `H = D·SubtreeH = 2·SubtreeH`, so shifting right by
    `SubtreeH` twice clears it — the top tree is unique and its root is the
    message-independent `pkRoot`. -/
theorem extractHtIndex_top_zero (digest : ByteVec 32) :
    extractHtIndex digest >>> Spec.SubtreeH >>> Spec.SubtreeH = 0 := by
  have hlt : extractHtIndex digest < 2 ^ Spec.H := by
    unfold extractHtIndex; exact readBitsLe_lt digest (Spec.K * Spec.A) Spec.H
  rw [← Nat.shiftRight_add, Nat.shiftRight_eq_div_pow]
  apply Nat.div_eq_of_lt
  have h18 : Spec.SubtreeH + Spec.SubtreeH = Spec.H := by decide
  rw [h18]; exact hlt

/-- **One honest hypertree layer's WOTS+C signature recovers its public key.**
    When `findCount` succeeded with `(count, d)`, the layer's honest WOTS chains
    (built from `d`'s digits) recover `keygenPk` — packages `wots_pk_roundtrip`
    with the `findCount` postconditions. Used for both D=2 layers. -/
theorem honest_layer_pk (seed skSeed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msg : ByteVec 16) (limit : Nat) (count : UInt32) (d : ByteVec 32)
    (hfc : findCount seed layer tree kp (ByteVec.pad16 msg) limit = some (count, d)) :
    Spec.Wots.pkFromSig seed layer tree kp msg
        { chains := Array.ofFn (n := Spec.L) fun i =>
            Spec.chainHash seed
              (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i.val))
              (Spec.wotsSecret skSeed layer tree kp (UInt32.ofNat i.val)) 0
              ((extractDigits d).getD i.val 0),
          chainsLen := Array.size_ofFn, count := count }
      = some (Spec.Wots.keygenPk seed skSeed layer tree kp) := by
  obtain ⟨hsum, hd⟩ := findCount_post seed layer tree kp (ByteVec.pad16 msg) limit count d hfc
  apply wots_pk_roundtrip seed skSeed layer tree kp msg _ (extractDigits d)
  · rw [← hd]
  · exact hsum
  · intro i hi
    have hlt := readBitsLe_lt d (i * Spec.LogW) Spec.LogW
    have hlw : (2 : Nat) ^ Spec.LogW = 8 := by decide
    have hw : Spec.W = 8 := by decide
    simp only [extractDigits, ofFn_getElem! _ i hi, Fin.val_mk]
    omega
  · intro i hi
    rw [ofFn_getElem! _ i hi]
    simp [Array.getElem!_eq_getD]

/-- **The honest FORS+C signature reconstructs to its public key.** Packages
    `fors_pk_roundtrip` for the exact `fors` record the reference signer emits;
    the forced-zero gate is supplied by `grindR_post` (as `hz`). -/
theorem honest_fors_pk (skSeed seed digest : ByteVec 32)
    (hz : readBitsLe digest ((Spec.K - 1) * Spec.A) Spec.A = 0) :
    Spec.Fors.reconstructForsPk seed digest
        { secrets := Array.ofFn fun i =>
            forsSecret skSeed (UInt32.ofNat (extractHtIndex digest)) (UInt32.ofNat i.val) (UInt32.ofNat ((extractForsIndices digest).getD i.val 0)),
          secretsLen := Array.size_ofFn,
          authPaths := Array.ofFn fun t =>
            forsMtAuthPath seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val)
              (fun j => forsSecret skSeed (UInt32.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val) (UInt32.ofNat j))
              ((extractForsIndices digest).getD t.val 0),
          authPathsLen := Array.size_ofFn }
      = some (Spec.Fors.computeForsPk seed (UInt64.ofNat (extractHtIndex digest))
          ((Array.ofFn (fun t : Fin (Spec.K - 1) =>
              forsMtNode seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val)
                (fun j => forsSecret skSeed (UInt32.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val) (UInt32.ofNat j)) Spec.A 0)).push
            (Spec.th seed
              (Spec.Adrs.forsNode (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat (Spec.K - 1)) 0 0)
              (((Array.ofFn (n := Spec.K) (fun i =>
                  forsSecret skSeed (UInt32.ofNat (extractHtIndex digest)) (UInt32.ofNat i.val)
                    (UInt32.ofNat ((extractForsIndices digest).getD i.val 0)))).getD (Spec.K - 1)
                (ByteVec.zero 16)).pad16)))) := by
  apply fors_pk_roundtrip seed digest _ (fun t j => forsSecret skSeed (UInt32.ofNat (extractHtIndex digest)) (UInt32.ofNat t) (UInt32.ofNat j))
  · rw [extractForsIndices_getD digest (Spec.K - 1) (by decide)]; exact hz
  · intro t ht
    rw [extractForsIndices_getD digest t (by omega)]; exact readBitsLe_lt digest (t * Spec.A) Spec.A
  · intro t ht; rw [ofFn_getD _ t (ByteVec.zero 16) (by omega)]
  · intro t ht; rw [ofFn_getD _ t #[] ht]

/-- A signing key is **well-formed** when its `pkRoot` is the honest hypertree
    top root (layer 1, the unique top tree 0). The Rust `SigningKey::keygen`
    enforces this at construction; within Lean it is the hypothesis under which
    the reference signer round-trips. -/
def WellFormed (sk : SigningKey) : Prop :=
  sk.pkRoot = mtNode (ByteVec.pad16 sk.pkSeed) (UInt32.ofNat 1) (UInt64.ofNat 0)
    (fun kp => Spec.Wots.keygenPk (ByteVec.pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 1)
      (UInt64.ofNat 0) (UInt32.ofNat kp)) Spec.SubtreeH 0

-- High `maxHeartbeats`: the assembly unifies the full signature term
-- (FORS + two D=2 layers) against the round-trip lemmas.
set_option maxHeartbeats 800000 in
/-- **`honest_consistent`** — the reference signer's output is accepted by the
    verifier, for any well-formed key. Discharges the `consistent sk` content of
    `verify_signs`. -/
theorem honest_consistent (sk : SigningKey) (hwf : WellFormed sk) :
    Spec.Theorems.consistent sk := by
  intro m sig hsign
  simp only [sign] at hsign
  split at hsign
  · exact absurd hsign (by simp)
  · next r digest hg =>
    split at hsign
    · exact absurd hsign (by simp)
    · next count0 d0 hf0 =>
      split at hsign
      · exact absurd hsign (by simp)
      · next count1 d1 hf1 =>
        rw [Option.some.injEq] at hsign
        subst hsign
        obtain ⟨hz, hdig⟩ := grindR_post sk.skSeed sk.pkSeed sk.pkRoot m 10000000 r digest hg
        simp only [Hypertree.verify, Hypertree.verifyWithDigest]
        rw [← hdig]
        have hcond : ¬ ((extractForsIndices digest).getD (Spec.K - 1) 0 ≠ 0) := by
          rw [extractForsIndices_getD digest (Spec.K - 1) (by decide), hz]; decide
        rw [if_neg hcond]
        simp only [honest_fors_pk sk.skSeed (ByteVec.pad16 sk.pkSeed) digest hz]
        -- The WOTS/auth-path hypotheses are left as `_` goals so the rewrite
        -- solves `forsPk`/`layers` from the goal FIRST (avoiding higher-order
        -- unification blowup), then we discharge them with everything concrete.
        rw [hypertree_roundtrip (ByteVec.pad16 sk.pkSeed) _ (extractHtIndex digest) _
              (fun kp => Wots.keygenPk (ByteVec.pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 0)
                (UInt64.ofNat (extractHtIndex digest >>> Spec.SubtreeH)) (UInt32.ofNat kp))
              (fun kp => Wots.keygenPk (ByteVec.pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 1)
                (UInt64.ofNat (extractHtIndex digest >>> Spec.SubtreeH >>> Spec.SubtreeH)) (UInt32.ofNat kp))
              _ _ _ _ _ _]
        · simp only [extractHtIndex_top_zero, decide_eq_true_eq]
          exact hwf.symm
        · exact honest_layer_pk (ByteVec.pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 0)
            (UInt64.ofNat (extractHtIndex digest >>> Spec.SubtreeH))
            (UInt32.ofNat (extractHtIndex digest &&& 1 <<< Spec.SubtreeH - 1)) _ 10000000 count0 d0 hf0
        · rfl
        · exact and_mask_lt _ Spec.SubtreeH
        · exact honest_layer_pk (ByteVec.pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 1)
            (UInt64.ofNat (extractHtIndex digest >>> Spec.SubtreeH >>> Spec.SubtreeH))
            (UInt32.ofNat (extractHtIndex digest >>> Spec.SubtreeH &&& 1 <<< Spec.SubtreeH - 1)) _
            10000000 count1 d1 hf1
        · rfl
        · exact and_mask_lt _ Spec.SubtreeH

end SphincsCVerify.Interpreter.C10
