/- Exact first-nonce Result semantics for the actual secret-keyed FORS search. -/
import Extracted.GrindRSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true

def FirstForsNonce (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (nonce : Std.U32) : Prop :=
  nonce.val < 10000000 ∧
  forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt nonce ∧
  ∀ earlier : Std.U32, earlier.val < nonce.val →
    ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt earlier

theorem first_fors_nonce_unique (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (a b : Std.U32) (ha : FirstForsNonce sk message seed root opt a)
    (hb : FirstForsNonce sk message seed root opt b) : a = b := by
  apply UScalar.eq_of_val_eq
  have hl : ¬ a.val < b.val := fun h => hb.2.2 a h ha.2.1
  have hr : ¬ b.val < a.val := fun h => ha.2.2 b h hb.2.1
  omega

def pureGrindR (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    Result (Std.Array Std.U8 16#usize × Std.Array Std.U8 32#usize) := by
  classical
  exact if h : ∃ c, FirstForsNonce sk message seed root opt c then
    let c := Classical.choose h
    .ok (forsRandomizer sk message opt c,
      forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt c)
  else .fail .assertionFailure

/-- The source search equals the first-nonce model, including exhaustion. -/
theorem firmware_grind_r_pure (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    fors.grind_r sk seed root message opt = pureGrindR sk message seed root opt := by
  classical
  rcases grind_r_total sk message seed root opt with ⟨c,hb,ha,hf,he⟩ | ⟨he,hr⟩
  · have hc : FirstForsNonce sk message seed root opt c := ⟨hb,ha,hf⟩
    have hex : ∃ c, FirstForsNonce sk message seed root opt c := ⟨c,hc⟩
    have hchoice := first_fors_nonce_unique sk message seed root opt
      (Classical.choose hex) c (Classical.choose_spec hex) hc
    simp only [pureGrindR, dif_pos hex, hchoice, he]
  · have hn : ¬ ∃ c, FirstForsNonce sk message seed root opt c := by
      rintro ⟨c,hb,ha,_⟩
      exact hr c hb ha
    simp only [pureGrindR, dif_neg hn, he]

theorem pure_grind_r_success (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize)
    (h : pureGrindR sk message seed root opt = .ok (r,digest)) :
    ∃ c, FirstForsNonce sk message seed root opt c ∧
      r = forsRandomizer sk message opt c ∧
      digest = forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt c := by
  classical
  unfold pureGrindR at h
  split at h
  · rename_i hex
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    exact ⟨Classical.choose hex, Classical.choose_spec hex, h.1.symm, h.2.symm⟩
  · cases h

end
end Extracted.Equiv
