(* A bounded list of explicit client guesses. Its contents are not assumed
   independent of the signer's private values. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer RawKeygen RawForsPathReplay RawSigner RawSignature EncodedSlices.
require import PrefixGuess PrefixHybrid FullSession ByteSession KeygenExhaustion ExposureLog.
require import ClientQueryLog ClientQueryDriver NodeDistribution.
import RealOrder.

lemma raw_address_width layer tree kind kp ci cp ha :
  size (address layer tree kind kp ci cp ha)=32.
proof. by rewrite /address !size_cat !be_width. qed.

lemma fors_leaf_guess_slot seed ht tree index secret :
  size seed=32 => size secret=16 =>
  take 16 (drop 64 (fors_leaf_input seed ht tree index secret))=secret.
proof.
  move=> hs hv.
  have h := slice_body (seed ++ address 0 ht 3 tree 0 0 index) secret (nseq 16 0).
  move: h; rewrite size_cat hs raw_address_width hv /fors_leaf_input /pad; smt(catA).
qed.

op client_guess_candidates (inputs : raw_input list) (signature : raw_signature) =
  map (fun x => take 16 (drop 64 x)) inputs ++
  map (fun tree => nth (nseq 16 0) signature.`2 tree) (range 0 12).

lemma client_guess_candidates_size inputs signature :
  size (client_guess_candidates inputs signature)=size inputs+12.
proof. by rewrite /client_guess_candidates size_cat !size_map size_range /=. qed.

lemma forwarded_leaf_is_candidate inputs signature seed ht tree index secret :
  size seed=32 => size secret=16 =>
  List.mem inputs (fors_leaf_input seed ht tree index secret) =>
  List.mem (client_guess_candidates inputs signature) secret.
proof.
  move=> hs hv hm; rewrite /client_guess_candidates mem_cat; left.
  apply mapP; exists (fors_leaf_input seed ht tree index secret); split; first exact hm.
  by simplify; rewrite (fors_leaf_guess_slot seed ht tree index secret hs hv).
qed.

lemma final_ordinary_value_is_candidate inputs (signature : raw_signature) tree :
  0<=tree<12 =>
  List.mem (client_guess_candidates inputs signature) (nth (nseq 16 0) signature.`2 tree).
proof.
  move=> ht; rewrite /client_guess_candidates mem_cat; right.
  apply mapP; exists tree; rewrite mem_range; smt().
qed.

lemma client_game_candidate_bound
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) qr :
  hoare [ClientQueryContext(A,O).run : FullLimits.raw_cap=qr /\ 0<=qr ==>
    size (client_guess_candidates ClientQueryLog.inputs ClientQueryLog.output.`2)<=qr+12].
proof.
  conseq (client_query_context_bound A O qr); smt(client_guess_candidates_size).
qed.

lemma fresh_node_client_candidates inputs signature :
  mu full_digest (fun d => List.mem (client_guess_candidates inputs signature) (node d)) <=
    (size inputs+12)%r*(1%r/2%r)^128.
proof.
  have h := node_history_mass (client_guess_candidates inputs signature).
  by rewrite client_guess_candidates_size in h.
qed.
