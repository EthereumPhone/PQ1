require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind WotsReferenceRoot VerifierWotsOpening VerifierWotsReplay RawRecoveryTrace.
require import RawWotsExtraction LayerWotsExtraction WotsKeyExtraction LayerBuildExtraction MemoNodeCollision PublicNodeZero.

lemma wire_counter_outside_signing_search :
  0<=10000000<4294967296 /\ !(0<=10000000<signing_budget).
proof. by rewrite /signing_budget. qed.

op colliding_history : (raw_input,digest) fmap =
  empty.[[0]<-nseq 256 false].[[1]<-nseq 256 false].
lemma distinct_retained_inputs_same_node :
  [0]<>[1] /\ [0] \in colliding_history /\ [1] \in colliding_history /\
  node (oget colliding_history.[[0]])=node (oget colliding_history.[[1]]) /\
  public_node_collision colliding_history.
proof.
  have h0 : colliding_history.[[0]]=Some (nseq 256 false)
    by rewrite /colliding_history !get_setE /=.
  have h1 : colliding_history.[[1]]=Some (nseq 256 false)
    by rewrite /colliding_history get_set_sameE.
  have hc : public_node_collision colliding_history.
  + rewrite /public_node_collision; exists [0] [1] (nseq 256 false) (nseq 256 false); smt().
  smt(domE).
qed.

lemma unequal_rows_equal_flatten :
  flatten [[0];[0;0]]=flatten [[0;0];[0]] /\ [[0];[0;0]]<>[[0;0];[0]].
proof. by simplify. qed.
