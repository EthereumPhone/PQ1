/- Actual WOTS generation loop: termination, all 43 positional endpoints,
   exact address domains, and ordered endpoint compression. -/
import Extracted.WotsKeygen.Funs
import Extracted.WotsSecretSpec
import Extracted.PkFromSigSpec

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

def wotsKeygenChain (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) (j : Nat) : Std.Array Std.U8 16#usize :=
  chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0)
    (wotsSecretPure sk layer tree kp ⟨BitVec.ofNat 32 j⟩) 0#u32 7#u32

def wotsKeygenChains (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) : List (Std.Array Std.U8 16#usize) :=
  (List.range 43).map (wotsKeygenChain seed sk layer tree kp)

def wotsKeygenPure (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) : Std.Array Std.U8 16#usize :=
  th_multi_pure seed (adrsArr layer tree 1 kp.val 0 0 0)
    ⟨wotsKeygenChains seed sk layer tree kp, by simp [wotsKeygenChains]; scalar_tac⟩

theorem wots_keygen_loop_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (base_adrs : Std.Array Std.U8 32#usize) (iter : core.ops.range.Range Std.Usize)
    (pk_elements : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (hbase : base_adrs.val.map (·.val) = specMakeAdrs layer.val tree.val 0 kp.val 0 0 0)
    (hend : iter.«end».val = 43) (hle : iter.start.val ≤ 43)
    (hpk : ∀ j, j < iter.start.val →
      pk_elements.val[j]! = wotsKeygenChain seed sk layer tree kp j) :
    wots.keygen_pk_loop iter seed sk layer tree kp base_adrs pk_elements
      ⦃ r => ∀ j, j < 43 → r.val[j]! = wotsKeygenChain seed sk layer tree kp j ⦄ := by
  unfold wots.keygen_pk_loop
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 43#usize) => s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 43#usize) =>
      s.1.«end».val = 43 ∧ s.1.start.val ≤ 43 ∧
      ∀ j, j < s.1.start.val → s.2.val[j]! = wotsKeygenChain seed sk layer tree kp j)
  · rintro ⟨it, pk⟩ ⟨hbnd, hsle, hinv⟩
    simp only at hbnd hsle hinv
    unfold wots.keygen_pk_loop.body
    simp only [lift, params.W]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact fun j hj => hinv j (by omega)
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hj42 : j.val ≤ 42 := by omega
      have hcastj : (UScalar.cast .U32 j).val = j.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hcast : UScalar.cast .U32 j = (⟨BitVec.ofNat 32 j.val⟩ : Std.U32) :=
        u32_eq_ofNat (by omega) hcastj
      let* ⟨sk_i, hsk⟩ ← wots_secret_spec sk layer tree kp (UScalar.cast .U32 j)
      let* ⟨chain_adrs, hchain⟩ ← set_chain_index_spec base_adrs (UScalar.cast .U32 j)
      rw [hbase, hcastj, specSetChainIndex_fresh] at hchain
      have hchain_eq : adrsArr layer tree 0 kp.val j.val 0 0 = chain_adrs :=
        adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ hchain
      step* <;> first | (simp only [UScalar.cast_val_eq]; scalar_tac) | scalar_tac | skip
      have hi3 : i3 = 7#usize := by apply UScalar.eq_of_val_eq; scalar_tac
      refine ⟨by rw [hend']; exact hbnd, by omega, ?_, by rw [hend']; omega⟩
      intro jj hjj
      rw [a1_post, Array.set_val_eq]
      have hpklen : pk.val.length = 43 := by simpa using pk.property
      by_cases hjb : jj = j.val
      · subst hjb
        rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, rfl⟩, a_post, ← hchain_eq, hsk, hcast, hi3]
        have hc7 : UScalar.cast .U32 7#usize = 7#u32 := by
          apply UScalar.eq_of_val_eq
          simp [UScalar.cast_val_eq]
        rw [hc7]
        rfl
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        apply hinv jj
        rw [hstart'] at hjj
        omega
  · exact ⟨hend, hle, hpk⟩

/-- Every input completes all 43 chains and compresses them in chain order. -/
@[step] theorem wots_keygen_pk_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) :
    wots.keygen_pk seed sk layer tree kp ⦃ r => r = wotsKeygenPure seed sk layer tree kp ⦄ := by
  unfold wots.keygen_pk
  simp only [params.ADRS_WOTS, params.ADRS_WOTS_PK, params.L]
  let* ⟨base, hbase⟩ ← make_adrs_spec
  let* ⟨chains, hchains⟩ ← wots_keygen_loop_spec seed sk layer tree kp base
    { start := 0#usize, «end» := 43#usize }
    (Array.repeat 43#usize (Array.repeat 16#usize 0#u8))
    (by simpa using hbase) (by simp) (by simp) (by simp)
  let* ⟨pk_adrs, hpkadrs⟩ ← make_adrs_spec
  simp only [lift]
  step*
  · have := chains.property; simp_all [Array.val_to_slice]
  have heq : adrsArr layer tree 1 kp.val 0 0 0 = pk_adrs :=
    adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ (by simpa using hpkadrs)
  have hc : chains.val = wotsKeygenChains seed sk layer tree kp := by
    apply List.ext_getElem
    · simp only [wotsKeygenChains, List.length_map, List.length_range]
      simpa using chains.property
    intro n h1 h2
    rw [← getElem!_pos chains.val n h1, hchains n (by simpa using h1)]
    simp only [wotsKeygenChains, List.getElem_map, List.getElem_range]
  rw [r_post, wotsKeygenPure, heq]
  exact congrArg (th_multi_pure seed pk_adrs) (Subtype.ext (by simpa [Array.to_slice] using hc))

end Extracted.Equiv
