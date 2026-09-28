(* The same initialized byte game yields the top-opening event, without
   adding oracle calls or choosing the final leaf before the adversary runs. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion RawKeygen RawMerkleRootWitness.
require import FullSession ByteSession MerkleRootWitness SessionTopExtraction.
require import MemoNodeCollision PublicNodeZero.

lemma prepared_top_reference seed0 :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    pad (node KeygenInputs.public_seed)=seed0 ==>
    exists root0, res.`3=seed0 /\ res.`4=pad root0 /\
      merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0].
proof.
  proc; wp; call (keygen_root_recorded seed0 1 0); auto; smt().
qed.

lemma full_context_top_extraction
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) seed0 :
  hoare [FullContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof.
  proc; seq 1 : (exists root0, inputs.`3=seed0 /\ inputs.`4=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (prepared_top_reference seed0); auto.
  elim* => root0; call (full_driver_top_extraction A seed0 root0); auto; smt().
qed.

lemma byte_context_top_extraction
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) seed0 :
  hoare [ByteContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof.
  conseq (byte_context_equiv A Independent) (full_context_top_extraction (ByteLift(A)) seed0).
  + move=> &m hm.
    exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}
      Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  smt().
qed.

lemma byte_game_top_extraction
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) seed0 :
  hoare [IndependentGame(ByteContext(A)).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_top_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof.
  proc; call (byte_context_top_extraction A seed0); inline Independent.init; auto.
qed.
