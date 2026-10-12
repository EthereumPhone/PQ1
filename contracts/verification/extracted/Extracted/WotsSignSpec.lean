/- Actual shuffled WOTS construction. Bounded count failure is kept explicit;
   the shuffle only schedules writes to canonical chain positions. -/
import Extracted.WotsSign.Funs
import Extracted.ShuffleOrder
import Extracted.FindCountSpec
import Extracted.WotsSecretSpec

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open sphincs_c10

noncomputable def wotsSignChain (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) (j : Nat) : Std.Array Std.U8 16#usize :=
  chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0)
    (wotsSecretPure sk layer tree kp ⟨BitVec.ofNat 32 j⟩) 0#u32
    ⟨BitVec.ofNat 32 (wotsDigit d j)⟩

noncomputable def wotsSignChains (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32) : Std.Array (Std.Array Std.U8 16#usize) 43#usize :=
  ⟨(List.range 43).map (wotsSignChain seed sk d layer tree kp), by simp⟩

attribute [local irreducible] wotsSignChain wotsSignChains

private theorem sign_chain_no_overflow (x : Std.U32) (hx : x.val < 8) :
    (0#u32).val + x.val ≤ Std.U32.max := by scalar_tac

private theorem sign_index_in_bounds (a : Std.Array α 43#usize) (x : Std.Usize)
    (hx : x.val < 43) : x.val < a.length := by scalar_tac

theorem wots_sign_loop_spec (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (digits : Std.Array Std.U8 43#usize) (base : Std.Array Std.U8 32#usize)
    (order : Std.Array Std.U8 64#usize) (iter : core.ops.range.Range Std.Usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (hdigits : ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j)
    (hbase : base.val.map (·.val) = specMakeAdrs layer.val tree.val 0 kp.val 0 0 0)
    (hp : shufflePermutation 43 order) (hend : iter.«end».val = 43) (hle : iter.start.val ≤ 43)
    (hprev : ∀ t, t < iter.start.val → sigma.val[(order.val[t]!).val]! =
      wotsSignChain seed sk d layer tree kp (order.val[t]!).val) :
    wots.sign_with_shuffle_loop iter seed sk layer tree kp digits base sigma order
      ⦃ r => ∀ t, t < 43 → r.val[(order.val[t]!).val]! =
        wotsSignChain seed sk d layer tree kp (order.val[t]!).val ⦄ := by
  unfold wots.sign_with_shuffle_loop
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 43#usize) => 43 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 43#usize) =>
      s.1.«end».val = 43 ∧ s.1.start.val ≤ 43 ∧
      ∀ t, t < s.1.start.val → s.2.val[(order.val[t]!).val]! =
        wotsSignChain seed sk d layer tree kp (order.val[t]!).val)
  · rintro ⟨it, sig⟩ ⟨hend, hle, hinv⟩
    simp only at hend hle hinv
    unfold wots.sign_with_shuffle_loop.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact fun t ht => hinv t (by omega)
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hj43 : j.val < 43 := by rw [hj]; omega
      let* ⟨byte, hbyte⟩ ← Array.index_usize_spec order j (by scalar_tac)
      have hby : byte = order.val[j.val]! := by
        rw [hbyte, getElem!_pos order.val j.val (by have := order.property; scalar_tac)]
      have hbyte43 : byte.val < 43 := by rw [hby]; exact shuffle_order_bound 43 order (by decide) hp j.val hj43
      have hidx : (UScalar.cast .Usize byte).val = byte.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hidx32 : (UScalar.cast .U32 (UScalar.cast .Usize byte)).val = byte.val := by
        rw [UScalar.cast_val_eq, hidx]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hcast : UScalar.cast .U32 (UScalar.cast .Usize byte) = (⟨BitVec.ofNat 32 byte.val⟩ : Std.U32) :=
        u32_eq_ofNat (by omega) hidx32
      let* ⟨secret, hs⟩ ← wots_secret_spec sk layer tree kp (UScalar.cast .U32 (UScalar.cast .Usize byte))
      let* ⟨adrs, hadrs⟩ ← set_chain_index_spec base (UScalar.cast .U32 (UScalar.cast .Usize byte))
      rw [hbase, hidx32, specSetChainIndex_fresh] at hadrs
      have hadeq : adrsArr layer tree 0 kp.val byte.val 0 0 = adrs := adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ hadrs
      have hidxlen : (UScalar.cast .Usize byte).val < digits.val.length := by
        rw [digits.property]
        change (UScalar.cast .Usize byte).val < 43
        omega
      let* ⟨digit, hdigit⟩ ← Array.index_usize_spec digits (UScalar.cast .Usize byte) hidxlen
      have hdv : digit.val = wotsDigit d byte.val := by
        rw [hdigit, ← getElem!_pos digits.val (UScalar.cast .Usize byte).val hidxlen, hidx]
        exact hdigits byte.val hbyte43
      have hd8 : digit.val < 8 := by rw [hdv]; exact wotsDigit_lt d byte.val
      have hdc : (UScalar.cast .U32 digit).val = wotsDigit d byte.val := by
        rw [UScalar.cast_val_eq]
        change digit.val % 4294967296 = wotsDigit d byte.val
        rw [Nat.mod_eq_of_lt (by omega), hdv]
      have hdcast := u32_eq_ofNat (n := wotsDigit d byte.val) (by have := wotsDigit_lt d byte.val; omega) hdc
      let* ⟨a, a_post⟩ ← hash.chain_hash_spec seed adrs secret 0#u32 (UScalar.cast .U32 digit)
        (sign_chain_no_overflow _ (by rw [hdc]; exact wotsDigit_lt d byte.val))
      let* ⟨a1, a1_post⟩ ← Array.update_spec sig (UScalar.cast .Usize byte) a
        (sign_index_in_bounds sig _ (by omega))
      have hvalue : a = wotsSignChain seed sk d layer tree kp byte.val := by
        rw [a_post, ← hadeq, hs, hcast, hdcast]
        exact (by unfold wotsSignChain; rfl)
      refine ⟨by rw [hend']; exact hend, by omega, ?_, by omega⟩
      intro t ht
      rw [a1_post, Array.set_val_eq, hidx]
      have ht43 : t < 43 := by omega
      have htv := shuffle_order_bound 43 order (by decide) hp t ht43
      by_cases he : (order.val[t]!).val = byte.val
      · rw [he, List.set_getElem!_eq _ _ _ _ ⟨by rw [sig.property]; exact hbyte43, rfl⟩, hvalue]
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        apply hinv t
        have hne : t ≠ j.val := by intro h; apply he; rw [h, ← hby]
        rw [hstart'] at ht
        rw [hj] at hne
        omega
  · exact ⟨hend, hle, hprev⟩
theorem wots_sign_from_count (seed sk d : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (c : Std.U32)
    (digits : Std.Array Std.U8 43#usize)
    (hsearch : wots.find_count seed layer tree kp (pad16p message) progress pct = .ok (c,d,digits))
    (hdigits : ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j) :
    wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct
      ⦃ r => r = (wotsSignChains seed sk d layer tree kp, c) ⦄ := by
  unfold wots.sign_with_shuffle
  simp only [params.ADRS_WOTS, params.L]
  let* ⟨padded, hpad⟩ ← pad16_spec message
  simp only [hpad, hsearch, bind_tc_ok]
  let* ⟨base, hb⟩ ← make_adrs_spec layer tree 0#u32 kp 0#u32 0#u32 0#u32
  let* ⟨order, ho⟩ ← shuffle_permutation_spec shuffle_seed 43#usize (by decide)
  let* ⟨sigma, hs⟩ ← wots_sign_loop_spec seed sk d layer tree kp digits base order
    { start := 0#usize, «end» := 43#usize }
    (Array.repeat 43#usize (Array.repeat 16#usize 0#u8)) hdigits
    (by simpa using hb) ho (by simp) (by simp) (by simp)
  have he : sigma = wotsSignChains seed sk d layer tree kp := by
    apply Subtype.ext
    unfold wotsSignChains
    change sigma.val = (List.range 43).map (wotsSignChain seed sk d layer tree kp)
    apply List.ext_getElem
    · simp only [List.length_map, List.length_range]
      exact sigma.property
    intro j hj hj'
    have hj43 : j < 43 := by simpa using hj'
    obtain ⟨t, ht, hti⟩ := shuffle_order_covers 43 order (by decide) ho j hj43
    have h := hs t ht
    rw [hti] at h
    rw [← getElem!_pos sigma.val j hj, h]
    simp
  exact he

/-- First accepted count, all43 honest chain values, and no dependence on the
    shuffle seed. The accepted-trial premise does not assume a signer result. -/
theorem wots_sign_first_success (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (c : Std.U32)
    (hbound : c.val < 10000000)
    (ha : grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c)
    (hf : ∀ earlier : Std.U32, earlier.val < c.val →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) earlier) :
    wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct
      ⦃ r => r = (wotsSignChains seed sk
        (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c) layer tree kp, c) ⦄ := by
  obtain ⟨⟨c',d,digits⟩, hsearch, hc, hd, hj⟩ := WP.spec_imp_exists
    (find_count_first_success seed (pad16p message) layer tree kp progress pct c hbound ha hf)
  simp only at hc hd hj
  subst c'
  have h := wots_sign_from_count seed sk d layer tree kp message shuffle_seed progress pct c digits hsearch hj
  simpa only [hd] using h

/-- The source's terminal panic remains an explicit assertion failure. -/
theorem wots_sign_exhausted (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8)
    (hr : ∀ c : Std.U32, c.val < 10000000 →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c) :
    wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct = .fail .assertionFailure := by
  obtain ⟨padded, hp, he⟩ := WP.spec_imp_exists (pad16_spec message)
  have hc := find_count_exhausted seed (pad16p message) layer tree kp progress pct hr
  unfold wots.sign_with_shuffle
  simp only [hp, bind_tc_ok, he, hc, bind_tc_fail]

/-- Every input either returns the first accepted count with its exact positional
    signature, or fails because the entire bounded interval was rejected. -/
theorem wots_sign_total (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    (∃ c : Std.U32,
      wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct =
        .ok (wotsSignChains seed sk (wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0)
          (pad16p message) c) layer tree kp, c) ∧
      c.val < 10000000 ∧
      grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c ∧
      ∀ earlier : Std.U32, earlier.val < c.val →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) earlier) ∨
    (wots.sign_with_shuffle seed sk layer tree kp message shuffle_seed progress pct = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) (pad16p message) c) := by
  rcases find_count_total seed (pad16p message) layer tree kp progress pct with
    ⟨c,d,digits,hsearch,hbound,ha,hf,hd,hj⟩ | ⟨_, hr⟩
  · obtain ⟨r, he, hp⟩ := WP.spec_imp_exists
      (wots_sign_first_success seed sk layer tree kp message shuffle_seed progress pct c hbound ha hf)
    exact Or.inl ⟨c, hp ▸ he, hbound, ha, hf⟩
  · exact Or.inr ⟨wots_sign_exhausted seed sk layer tree kp message shuffle_seed progress pct hr, hr⟩

/-- Reordering has no effect on either success bytes or bounded failure. -/
theorem wots_sign_shuffle_independent (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (message : Std.Array Std.U8 16#usize) (left right : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    wots.sign_with_shuffle seed sk layer tree kp message left progress pct =
      wots.sign_with_shuffle seed sk layer tree kp message right progress pct := by
  rcases wots_sign_total seed sk layer tree kp message left progress pct with
    ⟨c,he,hb,ha,hf⟩ | ⟨he,hr⟩
  · obtain ⟨r,he',hp⟩ := WP.spec_imp_exists
      (wots_sign_first_success seed sk layer tree kp message right progress pct c hb ha hf)
    rw [he, he', hp]
  · rw [he, wots_sign_exhausted seed sk layer tree kp message right progress pct hr]
end Extracted.Equiv
