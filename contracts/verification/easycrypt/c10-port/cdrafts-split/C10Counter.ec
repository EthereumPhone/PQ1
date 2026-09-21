(* Concrete verifier counter domain. Signing searches a strict prefix; a
   verifier may receive any u32. Standard-library Subtype's explicit
   insubN/insubT/valP/valK construction axioms remain in the trusted base. *)
require import AllCore List Ring.
require Subtype.

clone Subtype as U32 with
  type T <- int,
  op P x <- 0 <= x < 4294967296
  proof inhabited.
  realize inhabited by exists 0.

type counter = U32.sT.

op enum : counter list = map (oget \o U32.insub) (range 0 4294967296).

lemma enum_spec (c : counter) : count (pred1 c) enum = 1.
proof.
  rewrite /enum count_map /preim /(\o) /=.
  rewrite (eq_in_count _ (pred1 (U32.val c))).
  + move=> x //=; rewrite mem_range=> hx @/pred1; split=> <*>>.
    - by move: hx=> /U32.insubT; case: (U32.insub x).
    by rewrite U32.valK.
  move: (range_uniq 0 4294967296)=> /count_uniq_mem /(_ (U32.val c)) -> @/b2i.
  by rewrite mem_range U32.valP.
qed.

lemma enum_mem (c : counter) : c \in enum.
proof.
  have : 0 < count (pred1 c) enum by rewrite enum_spec.
  by move/has_count/hasP => [x [hx @/pred1 <-]].
qed.

lemma enum_uniq : uniq enum.
proof. by apply/count_mem_uniq => c; rewrite enum_mem enum_spec. qed.

lemma cardinality : size enum = 4294967296.
proof. by rewrite /enum size_map size_range. qed.

lemma cardinality_bound : size enum <= 2 ^ 32.
proof.
  by rewrite cardinality (_ : 32 = 2 * 2 * 2 * 2 * 2) 1://
    !IntID.exprM !IntID.expr2.
qed.

lemma enum_nth (c : counter) : nth witness enum (U32.val c) = c.
proof.
  rewrite /enum (nth_map 0) 1:size_range 1:U32.valP.
  by rewrite nth_range 1:U32.valP /(\o) /= U32.valK.
qed.

lemma rank_numeric (c : counter) : index c enum = U32.val c.
proof.
  by rewrite -{1}(enum_nth c) index_uniq 1:cardinality 1:U32.valP 1:enum_uniq.
qed.

op signing_budget : int = 10000000.
op signing_enum : counter list =
  map (oget \o U32.insub) (range 0 signing_budget).

lemma signing_prefix : enum = signing_enum ++
  map (oget \o U32.insub) (range signing_budget 4294967296).
proof.
  by rewrite /enum /signing_enum (range_cat signing_budget)
    1:/signing_budget 1:// 1:/signing_budget 1:// map_cat.
qed.

lemma signing_size : size signing_enum = signing_budget.
proof. by rewrite /signing_enum size_map size_range /signing_budget. qed.

lemma signing_step_fits_u32 (i : int) :
  0 <= i < signing_budget => 0 <= i + 1 < 4294967296.
proof. by rewrite /signing_budget; smt(). qed.
