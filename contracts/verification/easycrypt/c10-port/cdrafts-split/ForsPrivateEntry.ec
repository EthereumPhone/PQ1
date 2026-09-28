(* Existing private derivations persist through actual FORS tree construction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawFors.

lemma hash_keeps_private_entry key sd :
  hoare [Independent.hash : Independent.secrethistory.[key] = Some sd ==>
    Independent.secrethistory.[key] = Some sd].
proof. proc; sp 1; if; auto. qed.

lemma fors_keeps_private_entry key sd :
  hoare [PreparationView(Independent).fors : Independent.secrethistory.[key] = Some sd ==>
    Independent.secrethistory.[key] = Some sd].
proof. proc; inline *; sp; if; auto; smt(get_setE domE). qed.

module type ForsTree (O : PreparationOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : raw_input * raw_input list
    { O.hash, O.fors }
}.

lemma tree_keeps_private_entry (T <: ForsTree {-Independent}) key sd :
  hoare [T(PreparationView(Independent)).tree :
    Independent.secrethistory.[key] = Some sd ==> Independent.secrethistory.[key] = Some sd].
proof.
  proc (Independent.secrethistory.[key] = Some sd) => //.
  + exact (hash_keeps_private_entry key sd).
  exact (fors_keeps_private_entry key sd).
qed.

lemma fors_tree_keeps_private_entry key sd :
  hoare [RawFors(PreparationView(Independent)).tree :
    Independent.secrethistory.[key] = Some sd ==> Independent.secrethistory.[key] = Some sd].
proof. exact (tree_keeps_private_entry RawFors key sd). qed.
