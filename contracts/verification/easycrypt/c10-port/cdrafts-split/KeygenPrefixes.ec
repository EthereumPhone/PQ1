(* WOTS/FORS private derivations share the same secret prefix as R, but their
   distinct deployed tags prevent preparation from filling R-tail entries. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter C10Randomizer.
require import PrefixGuess PrefixHybrid RawTrial RoleGrind RTailFresh.

op wots_tag = [119;111;116;115].
op fors_tag = [102;111;114;115].
op no_r_tails (h : (raw_input,digest) fmap) =
  forall tail, tail \in h => head 0 tail <> 82.

module type PreparationOracle = {
  proc hash(x : raw_input) : digest
  proc wots(tail : raw_input) : digest
  proc fors(tail : raw_input) : digest
}.
module PreparationView (O : PrefixOracle) = {
  proc hash = O.hash
  proc wots(tail : raw_input) : digest = {
    var out; out <@ O.derive(wots_tag ++ tail); return out;
  }
  proc fors(tail : raw_input) : digest = {
    var out; out <@ O.derive(fors_tag ++ tail); return out;
  }
}.
module type Preparation (O : PreparationOracle) = {
  proc run() : raw_input * raw_input * raw_input * raw_input
    { O.hash, O.wots, O.fors }
}.

lemma derive_preserves_no_r :
  hoare[Independent.derive : no_r_tails Independent.secrethistory /\ head 0 tail <> 82 ==>
    no_r_tails Independent.secrethistory].
proof.
  proc; if; auto; rewrite /no_r_tails; smt(FMap.mem_set).
qed.
lemma hash_preserves_no_r :
  hoare[Independent.hash : no_r_tails Independent.secrethistory ==>
    no_r_tails Independent.secrethistory].
proof. by proc; sp 1; if; auto. qed.

lemma wots_preserves_no_r :
  hoare[PreparationView(Independent).wots : no_r_tails Independent.secrethistory ==>
    no_r_tails Independent.secrethistory].
proof. by proc; call derive_preserves_no_r; auto; rewrite /wots_tag /=. qed.
lemma fors_preserves_no_r :
  hoare[PreparationView(Independent).fors : no_r_tails Independent.secrethistory ==>
    no_r_tails Independent.secrethistory].
proof. by proc; call derive_preserves_no_r; auto; rewrite /fors_tag /=. qed.

lemma preparation_preserves_no_r (P <: Preparation {-Independent}) :
  hoare[P(PreparationView(Independent)).run : no_r_tails Independent.secrethistory ==>
    no_r_tails Independent.secrethistory].
proof.
  proc (no_r_tails Independent.secrethistory) => //.
  + exact hash_preserves_no_r.
  + exact wots_preserves_no_r.
  exact fors_preserves_no_r.
qed.

lemma no_r_future_fresh h random message :
  no_r_tails h => future_fresh h random message 0.
proof.
  rewrite /no_r_tails /future_fresh => hh j hj.
  apply negP => hin; have ht := hh _ hin.
  by move: ht; rewrite /r_query /r_tail /=.
qed.
