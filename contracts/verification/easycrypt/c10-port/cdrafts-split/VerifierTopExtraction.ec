(* Successful complete verification selects a reference from actual keygen. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawLayer RawSigner RawSignature RawCountRecorded.
require import PersistentGrind AcceptedContexts MerkleRootWitness SignerCoordinates SignerComponentHistory.
require import RootSessionHistory RootExtractionHistory TopVerifierOpening MemoNodeCollision PublicNodeZero.

lemma verifier_extracts_top_opening seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      verified_top_opening Independent.rawhistory Independent.secrethistory seed0 root0 message0 sig0].
proof.
  proc; seq 1 : (seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 /\
    Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some digest).
  + call (_ : x=hmsg_input seed0 (pad root0) (pad sig0.`1) message0 /\
        merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
        merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 /\
        Independent.rawhistory.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some res).
    - conseq (hash_records_input (hmsg_input seed0 (pad root0) (pad sig0.`1) message0))
        (root_hash_preserved seed0 1 0 root0); smt().
    auto.
  exists* Independent.rawhistory,Independent.secrethistory,digest; elim* => h0 s0 d0.
  sp 1; if; last auto.
  wp; while (seed=seed0 /\ root=pad root0 /\ sig=sig0 /\ signature_width sig0 /\
    digest=d0 /\ accept_digest d0 /\ ht=hypertree_index d0 /\ 0<=layer<=2 /\
    idx_tree=signer_tree ht layer /\
    merkle_root_witness h0 s0 seed0 1 0 root0 /\
    h0.[hmsg_input seed0 (pad root0) (pad sig0.`1) message0]=Some d0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (layer=2 => current=root0 => public_node_collision Independent.rawhistory \/
      public_node_zero Independent.rawhistory \/
      top_layer_opening Independent.rawhistory Independent.secrethistory seed0 d0 sig0)).
  + exists* layer,current; elim* => k m0.
    case (k=0).
    - wp; call (layer_recovery_extends RawLayer s0 h0); auto.
    wp; call (layer_extracts_from_retained_root seed0 1 0 (hypertree_index d0 %/512) m0
      (nth ([],0,[]) sig0.`4 1) root0 h0 s0).
    auto; rewrite /signature_width /signer_tree /top_layer_opening.
    smt(hypertree_index_range allP mem_nth pdiv_small modz_small divz_ge0 ltz_divLR).
  wp; call (forest_recovery_extends RawForest s0 h0); auto.
  rewrite /signer_tree /verified_top_opening /pad /extends;
    smt(extends_refl catIs).
qed.
