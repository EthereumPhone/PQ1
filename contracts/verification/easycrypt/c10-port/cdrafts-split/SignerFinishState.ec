(* A finish-loop invariant linking the stored components to the prior root. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawForest RawLayer RawSigner.
require import PersistentGrind MerkleRootWitness ForestOpening LayerSignOpening SignerCoordinates SignerLayerTrace.

op signer_finish_state h s seed digest (forest : raw_input list * raw_input list list * raw_input)
    values layers k current root =
  merkle_root_witness h s seed 1 0 root /\
  forest_opening h seed (hypertree_index digest) digest forest.`1 forest.`2 forest.`3 /\
  signer_layer_trace h s seed (hypertree_index digest) layers values k /\
  nth [] values 0=forest.`3 /\ current=nth [] values k /\ (k=2 => current=root).

lemma finish_state_extends h h' s s' seed digest forest values layers k current root :
  extends h h' => extends s s' =>
  signer_finish_state h s seed digest forest values layers k current root =>
  signer_finish_state h' s' seed digest forest values layers k current root.
proof.
  rewrite /signer_finish_state; smt(merkle_root_witness_extends forest_opening_extends signer_trace_extends).
qed.

lemma finish_state_initial h s seed digest (forest : raw_input list * raw_input list list * raw_input) root :
  merkle_root_witness h s seed 1 0 root =>
  forest_opening h seed (hypertree_index digest) digest forest.`1 forest.`2 forest.`3 =>
  signer_finish_state h s seed digest forest [forest.`3] [] 0 forest.`3 root.
proof. rewrite /signer_finish_state /=; smt(signer_trace_empty). qed.

lemma finish_state_step h s seed digest forest values layers k current root signature next :
  0<=k<2 => signer_finish_state h s seed digest forest values layers k current root =>
  layer_opening h s seed k (signer_tree (hypertree_index digest) (k+1))
    (signer_tree (hypertree_index digest) k %%512) current signature next =>
  (k=1 => next=root) =>
  signer_finish_state h s seed digest forest (rcons values next) (rcons layers signature) (k+1) next root.
proof.
  move=> hk; rewrite /signer_finish_state; move=> [hr [hf [ht [hfirst [hcur htop]]]]] ho hn.
  have hnew := signer_trace_step h s seed (hypertree_index digest) layers values k signature next _ ht _.
  + smt().
  + smt().
  have hv : size values=k+1 by move: ht; rewrite /signer_layer_trace; smt().
  rewrite !nth_rcons hv; smt().
qed.

op signer_finish_opening h s seed digest (signature : raw_signature) root =
  exists values, forest_opening h seed (hypertree_index digest) digest signature.`2 signature.`3 (nth [] values 0) /\
    signer_layer_trace h s seed (hypertree_index digest) signature.`4 values 2 /\ nth [] values 2=root.

lemma finish_state_complete h s seed digest (forest : raw_input list * raw_input list list * raw_input)
    values layers current root randomizer :
  signer_finish_state h s seed digest forest values layers 2 current root =>
  signer_finish_opening h s seed digest (randomizer,forest.`1,forest.`2,layers) root.
proof.
  rewrite /signer_finish_state /signer_finish_opening /=; move=> [hr [hf [ht [ha [hb hc]]]]].
  exists values; smt().
qed.
