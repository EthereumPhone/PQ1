/- Pure cryptographic fields of a signer layer, with bounded failure retained. -/
import Extracted.WotsSignRecovery
import Extracted.XmssAuthRecovery
import Extracted.SignLayerSerializeCaller

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option pp.explicit true
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
attribute [local irreducible] wotsSignChains xmssRootNode
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

def FirstWotsCount (seed : Std.Array Std.U8 32#usize) (layer : Std.U32)
    (tree : Std.U64) (leaf : Std.U32) (message : Std.Array Std.U8 16#usize)
    (count : Std.U32) : Prop :=
  count.val < 10000000 ∧
  grindAccept seed (adrsArr layer tree 0 leaf.val 0 0 0) (pad16p message) count ∧
  ∀ earlier : Std.U32, earlier.val < count.val →
    ¬ grindAccept seed (adrsArr layer tree 0 leaf.val 0 0 0) (pad16p message) earlier

theorem first_wots_count_unique (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32)
    (message : Std.Array Std.U8 16#usize) (left right : Std.U32)
    (hl : FirstWotsCount seed layer tree leaf message left)
    (hr : FirstWotsCount seed layer tree leaf message right) : left = right := by
  apply UScalar.eq_of_val_eq
  rcases hl with ⟨_, ha, hf⟩
  rcases hr with ⟨_, ha', hf'⟩
  have hle : ¬ left.val < right.val := fun h => hf' left h ha
  have hge : ¬ right.val < left.val := fun h => hf right h ha'
  omega

def pureWotsSign (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32)
    (tree : Std.U64) (leaf : Std.U32) (message : Std.Array Std.U8 16#usize) :
    Result (WotsChains × Std.U32) := by
  classical
  exact if h : ∃ c, FirstWotsCount seed layer tree leaf message c then
    let c := Classical.choose h
    .ok (wotsSignChains seed sk
      (wots_digest_pure seed (adrsArr layer tree 0 leaf.val 0 0 0) (pad16p message) c)
      layer tree leaf, c)
  else .fail .assertionFailure

/-- Equality for every input, including exhausted count searches. -/
theorem firmware_wots_sign_pure (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle_seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    wots.sign_with_shuffle seed sk layer tree leaf message shuffle_seed progress pct =
      pureWotsSign seed sk layer tree leaf message := by
  classical
  rcases wots_sign_total seed sk layer tree leaf message shuffle_seed progress pct with
    ⟨c, he, hb, ha, hf⟩ | ⟨he, hr⟩
  · have hc : FirstWotsCount seed layer tree leaf message c := ⟨hb, ha, hf⟩
    have hex : ∃ c, FirstWotsCount seed layer tree leaf message c := ⟨c, hc⟩
    have hchoice := first_wots_count_unique seed layer tree leaf message
      (Classical.choose hex) c (Classical.choose_spec hex) hc
    simp only [pureWotsSign, dif_pos hex, hchoice, he]
  · have hn : ¬ ∃ c, FirstWotsCount seed layer tree leaf message c := by
      rintro ⟨c, hb, ha, _⟩
      exact hr c hb ha
    simp only [pureWotsSign, dif_neg hn, he]

theorem derived_wots_sign_bind {α : Type} (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32)
    (message : Std.Array Std.U8 16#usize) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (label : Slice Std.U8) (progress : hypertree.ProgressSink) (pct : Std.U8)
    (continuation : (WotsChains × Std.U32) → Result α) :
    (do let derived ← sphincs_c10.shuffle.ShuffleSeed.derive shuffle label
        let fields ← wots.sign_with_shuffle seed sk layer tree leaf message derived progress pct
        continuation fields) =
      (do let fields ← pureWotsSign seed sk layer tree leaf message
          continuation fields) := by
  have hs : sphincs_c10.shuffle.ShuffleSeed.derive shuffle label ⦃ _ => True ⦄ := by
    unfold sphincs_c10.shuffle.ShuffleSeed.derive
    split <;> simp only [WP.spec_ok]
  obtain ⟨derived, hd, _⟩ := WP.spec_imp_exists hs
  rw [hd]
  simp only [bind_tc_ok, firmware_wots_sign_pure]

def xmssSigningPath (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) : XmssAuth :=
  ⟨(List.range 9).map (fun h =>
    xmssRootNode seed sk layer tree h (xmssAuthSibling leaf.val h)), by simp⟩

theorem xmss_signing_path_get (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) (h : Nat) (hh : h < 9) :
    (xmssSigningPath seed sk layer tree leaf).val[h]! =
      xmssRootNode seed sk layer tree h (xmssAuthSibling leaf.val h) := by
  simp [xmssSigningPath, hh]

theorem firmware_xmss_signing_path (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64) (progress : hypertree.ProgressSink)
    (pct_lo pct_hi : Std.U8) (hleaf : leaf.val < 512) :
    merkle.build_subtree_with_auth seed sk layer tree leaf progress pct_lo pct_hi =
      .ok (xmssSigningPath seed sk layer tree leaf, xmssRootNode seed sk layer tree 9 0) := by
  obtain ⟨⟨path, root⟩, he, hroot, hp⟩ := WP.spec_imp_exists
    (xmss_build_auth_spec seed sk layer leaf tree progress pct_lo pct_hi hleaf)
  dsimp only at hroot hp
  have hpath : path = xmssSigningPath seed sk layer tree leaf := by
    apply Subtype.ext
    apply List.ext_getElem
    · rw [path.property, (xmssSigningPath seed sk layer tree leaf).property]
    intro h hh hh'
    have hb : h < 9 := by simpa only [path.property] using hh
    rw [← getElem!_pos path.val h hh,
      ← getElem!_pos (xmssSigningPath seed sk layer tree leaf).val h hh',
      hp h hb, xmss_signing_path_get seed sk layer tree leaf h hb]
  simpa only [hpath, hroot] using he

theorem pure_wots_recovery (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32)
    (message : Std.Array Std.U8 16#usize) (chains : WotsChains) (count : Std.U32)
    (h : pureWotsSign seed sk layer tree leaf message = .ok (chains, count)) :
    wots.pk_from_sig seed layer tree leaf message chains count =
      .ok (wotsKeygenPure seed sk layer tree leaf) := by
  classical
  unfold pureWotsSign at h
  split at h
  · rename_i hex
    have hc := Classical.choose_spec hex
    have he := Result.ok.inj h
    have hchains := congrArg Prod.fst he
    have hcount := congrArg Prod.snd he
    dsimp only at hchains hcount
    obtain ⟨r, hr, hp⟩ := WP.spec_imp_exists
      (wots_honest_signature_recovery seed sk layer tree leaf message
        (Classical.choose hex) hc.2.1)
    rw [hchains, hcount, hp] at hr
    exact hr
  · cases h

theorem xmss_signing_path_recovery (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.U32) (hleaf : leaf.val < 512) :
    merkle.verify_auth_path seed layer tree (wotsKeygenPure seed sk layer tree leaf)
      leaf (xmssSigningPath seed sk layer tree leaf) =
      .ok (xmssRootNode seed sk layer tree 9 0) := by
  obtain ⟨r, hr, hp⟩ := WP.spec_imp_exists (verify_auth_path_spec seed layer tree
    (wotsKeygenPure seed sk layer tree leaf) leaf (xmssSigningPath seed sk layer tree leaf))
  rw [xmss_auth_recovery_root seed sk layer leaf tree hleaf _ _ rfl
    (xmss_signing_path_get seed sk layer tree leaf)] at hp
  simpa only [hp] using hr

end
end Extracted.Equiv
