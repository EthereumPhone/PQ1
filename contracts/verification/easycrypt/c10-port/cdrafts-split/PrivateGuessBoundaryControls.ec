(* Positive boundary witnesses. These are not secrecy or forgery bounds. *)
require import AllCore List.
require import C10RawOracle RawKeygen RawFors ForsPrivateLeaves ForsInputSeparation.
require import RawSigner PrefixGuess PrefixHybrid FullSession ExposureLog ClientQueryLog.
require import ClientGuessCandidates.

lemma ordinary_and_special_inputs_differ ht i j :
  0<=ht<262144 => 0<=i<2048 => 0<=j<2048 =>
  fors_private_key ht 11 i <> fors_private_key ht 12 j.
proof. smt(fors_private_key_injective). qed.

lemma repeated_coordinate_same_input ht tree index :
  fors_private_key ht tree index=fors_private_key ht tree index.
proof. trivial. qed.

lemma no_queries_still_has_twelve_candidates signature :
  size (client_guess_candidates [] signature)=12.
proof. by rewrite client_guess_candidates_size. qed.

lemma one_query_has_thirteen_candidates x signature :
  size (client_guess_candidates [x] signature)=13.
proof. by rewrite client_guess_candidates_size. qed.

lemma blocked_client_query_not_recorded
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 x0 cap :
  hoare [QueryExposureSession(O).hash :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\ FullSession.raw_calls=cap /\ FullSession.raw_limit=cap ==>
    ClientQueryLog.inputs=inputs0].
proof. conseq (client_query_hash_exact O inputs0 x0 cap cap); smt(). qed.

lemma forwarded_client_query_recorded
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 x0 :
  hoare [QueryExposureSession(O).hash :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\ FullSession.raw_calls=0 /\ FullSession.raw_limit=1 ==>
    ClientQueryLog.inputs=rcons inputs0 x0].
proof. conseq (client_query_hash_exact O inputs0 x0 0 1); smt(). qed.
