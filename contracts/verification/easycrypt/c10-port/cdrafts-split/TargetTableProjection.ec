(* Passive opening observation and an exact split of one memoized private entry. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen KeygenPrefixes.
require import ForsPrivateLeaves ForsLeafView TargetOracleSplit TargetByteView.

module OriginalTargetState = { var revealed : bool }.
module ObservedTarget (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive(tail : raw_input) : digest = {
    var y;
    OriginalTargetState.revealed <- OriginalTargetState.revealed \/ tail=TargetConfig.input;
    y <@ O.derive(tail); return y;
  }
  proc leaf = ConcreteTarget(O).leaf
  proc secret(ht tree index : int) : raw_input = {
    var sd; sd <@ derive(fors_private_key ht tree index); return node sd;
  }
}.
op selected_table (target : raw_input) (value : digest)
  (private others : (raw_input,digest) fmap) =
  private.[target]=Some value /\
  forall x, x<>target => private.[x]=others.[x].

lemma selected_table_initial target value :
  selected_table target value empty.[target <- value] empty.
proof. rewrite /selected_table; smt(get_setE). qed.
lemma selected_table_other target value private others x y :
  selected_table target value private others => x<>target =>
  selected_table target value private.[x <- y] others.[x <- y].
proof. rewrite /selected_table; smt(get_setE). qed.
lemma selected_table_lookup target value private others x :
  selected_table target value private others => x<>target =>
  (x \in private)=(x \in others).
proof. rewrite /selected_table; smt(domE). qed.

lemma observed_target_derive_projection :
  equiv [ObservedTarget(Independent).derive ~ RealTargetOracle.derive :
    ={arg,glob TargetConfig} /\ OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2} ==>
    ={res,glob TargetConfig} /\ OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2}].
proof.
  proc; inline Independent.derive OtherPrivate.derive.
  sp 2 0; if{2}.
  + rcondf{1} 1; first by auto; rewrite /selected_table; smt(domE).
    auto; rewrite /selected_table; smt().
  sp 0 1; if.
  + auto; smt(selected_table_lookup).
  + auto; smt(selected_table_other get_set_sameE).
  auto; rewrite /selected_table; smt().
qed.

lemma observed_target_hash_projection :
  equiv [ObservedTarget(Independent).hash ~ RealTargetOracle.hash :
    ={arg,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} ==>
    ={res,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2}].
proof. proc; inline *; sp 1 2; if; auto; smt(). qed.

lemma observed_target_leaf_projection :
  equiv [ObservedTarget(Independent).leaf ~ RealTargetOracle.leaf :
    ={arg,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2} ==>
    ={res,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2}].
proof.
  proc; wp; call (_ : Independent.rawhistory{1}=Shared.history{2}); first by sim.
  inline *; sp 2 1; if{2}.
  + rcondf{1} 1; first by auto; rewrite /selected_table /fors_private_key; smt(domE).
    auto; rewrite /selected_table /fors_private_key; smt().
  sp 0 1; if.
  + auto; rewrite /fors_private_key; smt(selected_table_lookup).
  + auto; rewrite /fors_private_key; smt(selected_table_other get_set_sameE).
  auto; rewrite /selected_table /fors_private_key; smt().
qed.

lemma observed_target_secret_projection :
  equiv [ObservedTarget(Independent).secret ~ RealTargetOracle.secret :
    ={arg,glob TargetConfig} /\ OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2} ==>
    ={res,glob TargetConfig} /\ OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2}].
proof. proc; call observed_target_derive_projection; auto. qed.

lemma observed_target_context_projection
  (A <: TargetContext {-Independent,-Shared,-OtherPrivate,-RealTargetPrivate,
    -RealTargetOracle,-OriginalTargetState,-TargetConfig}) :
  equiv [A(ObservedTarget(Independent)).run ~ A(RealTargetOracle).run :
    ={glob A,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2} ==>
    ={res,glob A,glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2}].
proof.
  proc (={glob TargetConfig} /\ Independent.rawhistory{1}=Shared.history{2} /\
    OriginalTargetState.revealed{1}=RealTargetOracle.revealed{2} /\
    selected_table TargetConfig.input{1} RealTargetPrivate.value{2}
      Independent.secrethistory{1} OtherPrivate.history{2}) => //.
  + conseq observed_target_hash_projection; smt().
  + conseq observed_target_derive_projection; smt().
  + conseq observed_target_leaf_projection; smt().
  conseq observed_target_secret_projection; smt().
qed.

lemma target_opening_observer_projection
  (A <: TargetContext {-OriginalTargetState,-TargetConfig})
  (O <: PrefixOracle {-A,-OriginalTargetState,-TargetConfig}) :
  equiv [A(ConcreteTarget(O)).run ~ A(ObservedTarget(O)).run :
    ={glob A,glob O,glob TargetConfig} ==> ={res,glob A,glob O,glob TargetConfig}].
proof.
  proc (={glob O,glob TargetConfig}) => //.
  + by sim.
  + proc*; inline ObservedTarget(O).derive; wp; call (_ : true); auto.
  + by sim.
  proc; inline ObservedTarget(O).derive PreparationView(O).fors.
  wp; call (_ : true).
  auto; rewrite /fors_private_key.
qed.
