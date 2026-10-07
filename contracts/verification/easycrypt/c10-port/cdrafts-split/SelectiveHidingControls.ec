(* Executable proof witnesses for openings, commitment replay, and internal leaves. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawFors ForsPrivateLeaves.
require import LeafCommitmentHybrid LeafOpeningBound TargetOracleSplit.

module RevealCandidate (O : LeafOpeningOracle) = {
  proc run() : raw_input list = { var key; key <@ O.reveal(); return [key]; }
}.
module EmptyCandidate (O : LeafOpeningOracle) = {
  proc run() : raw_input list = { return []; }
}.
lemma opened_candidate_is_rejected :
  hoare [RealUnopenedLeafGuess(RevealCandidate).run : true ==> !res].
proof.
  proc; inline RevealCandidate(RealLeafOpening).run RealLeafOpening.reveal Shared.init; auto.
qed.
lemma empty_candidate_is_rejected :
  hoare [RealUnopenedLeafGuess(EmptyCandidate).run : true ==> !res].
proof. proc; inline EmptyCandidate(RealLeafOpening).run Shared.init; auto. qed.

lemma leaf_commitment_records h prefix0 key0 :
  hoare [LeafCommitmentReal.derive : Shared.history=h /\ prefix=prefix0 /\ LeafCommitmentReal.key=key0 ==>
    Shared.history.[prefix0 ++ pad key0]=Some res].
proof. proc; call (hash_history h (prefix0 ++ pad key0)); auto. qed.
lemma leaf_commitment_replays prefix0 key0 value :
  hoare [LeafCommitmentReal.derive : Shared.history.[prefix0 ++ pad key0]=Some value /\
    prefix=prefix0 /\ LeafCommitmentReal.key=key0 ==> res=value].
proof.
  proc; inline Shared.hash; rcondf 3; first by auto; smt(domE).
  auto; smt().
qed.
module RepeatCommitment = {
  proc run(prefix : raw_input) : bool = {
    var first, second;
    first <@ LeafCommitmentReal.derive(prefix);
    second <@ LeafCommitmentReal.derive(prefix);
    return first=second;
  }
}.
lemma repeated_commitment_same_value : hoare [RepeatCommitment.run : true ==> res].
proof.
  proc; exists* prefix,LeafCommitmentReal.key; elim* => p k.
  seq 1 : (prefix=p /\ LeafCommitmentReal.key=k /\ Shared.history.[p ++ pad k]=Some first).
  + exists* Shared.history; elim* => h; call (leaf_commitment_records h p k); auto.
  exists* first; elim* => value; call (leaf_commitment_replays p k value); auto.
qed.
lemma internal_leaf_preserves_unopened :
  hoare [RealTargetOracle.leaf : !RealTargetOracle.revealed ==> !RealTargetOracle.revealed].
proof.
  proc; call (_ : true ==> true); first by trivial.
  sp 1; if; auto; call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma selected_secret_marks_open :
  hoare [RealTargetOracle.secret : fors_private_key ht tree index=TargetConfig.input ==>
    RealTargetOracle.revealed /\ res=node RealTargetPrivate.value].
proof.
  proc; inline RealTargetOracle.derive; rcondt 2; first by auto.
  auto.
qed.
