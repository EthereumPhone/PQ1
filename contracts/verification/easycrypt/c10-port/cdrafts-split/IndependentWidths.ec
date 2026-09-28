(* Well-sized memo tables are preserved by the actual independent oracle. *)
require import AllCore List Distr DList FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.

op independent_tables_valid public private = valid_history public /\ valid_history private.

lemma independent_hash_width :
  hoare [Independent.hash : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof.
  proc; sp 1; if; auto => />.
  + move=> &m hp hs0 hn y hy; have hs : size y=256
      by move: hy; rewrite /full_digest supp_dlist /=; smt().
    move: hp hs0; rewrite /valid_history; smt(get_setE get_set_sameE).
  move=> &m hp hs0 hn; move: hp hs0; rewrite /valid_history; smt(domE).
qed.
lemma independent_derive_width :
  hoare [Independent.derive : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof.
  proc; if; auto => />.
  + move=> &m hp hs0 hn y hy; have hs : size y=256
      by move: hy; rewrite /full_digest supp_dlist /=; smt().
    move: hp hs0; rewrite /valid_history; smt(get_setE get_set_sameE).
  move=> &m hp hs0 hn; move: hp hs0; rewrite /valid_history; smt(domE).
qed.
lemma preparation_wots_valid :
  hoare [PreparationView(Independent).wots :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; call independent_derive_width; auto; smt(). qed.

module type WidthKeygen (O : PreparationOracle) = {
  proc root(seed : raw_input, layer tree : int) : raw_input { O.hash, O.wots }
}.
lemma width_keygen_valid (K <: WidthKeygen {-Independent}) :
  hoare [K(PreparationView(Independent)).root :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  + conseq independent_hash_width; smt().
  exact preparation_wots_valid.
qed.
lemma independent_init_valid :
  hoare [Independent.init : true ==> independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; auto; rewrite /independent_tables_valid /valid_history; smt(FMap.emptyE). qed.
