(* A conservative node domain: omit H_msg and the address-kind-zero
   128-byte count inputs, but retain every other arbitrary raw input. *)
require import AllCore List.
require import C10RawOracle C10HashDomains RawKeygen HmsgShapes.
require import IndependentWidths RawSignature C10Bytes ClientGuessCandidates ForsInputSeparation.

op node_query (x : raw_input) =
  size x <> 160 /\ (size x <> 128 \/ take 4 (drop 44 x) <> be 4 0).

lemma node_query_other_width x :
  size x <> 160 => size x <> 128 => node_query x.
proof. by rewrite /node_query; smt(). qed.

lemma node_query_no_hmsg seed root r message :
  size seed=32 => size root=32 => size r=32 => size message=32 =>
  !node_query (hmsg_input seed root r message).
proof. rewrite /node_query; smt(hmsg_width). qed.

lemma node_input_kind seed layer tree kind kp ci cp ha payload :
  size seed=32 =>
  take 4 (drop 44 (seed ++ address layer tree kind kp ci cp ha ++ payload)) = be 4 kind.
proof.
  move=> hs; rewrite /address -!catA.
  rewrite drop_cat hs /= drop_cat be_width //= drop_cat be_width //= drop0.
  by rewrite take_cat be_width //= take0 cats0.
qed.

lemma node_query_no_count seed layer tree kp message count :
  size seed=32 => size message=16 =>
  !node_query (seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 count).
proof.
  move=> hs hm.
  have hw := hash_count_width seed (address layer tree 0 kp 0 0 0) message count
    hs (raw_address_width _ _ _ _ _ _ _) hm.
  have hk := node_input_kind seed layer tree 0 kp 0 0 0 (pad message ++ be 32 count) hs.
  by rewrite /node_query hw /= -catA hk.
qed.

lemma node_query_chain seed a value :
  size seed=32 => size a=32 => size value=16 => node_query (seed ++ a ++ pad value).
proof. move=> hs ha hv; apply node_query_other_width; smt(hash_chain_width). qed.

lemma node_query_pair seed layer tree kind kp ci cp ha lhs rhs :
  size seed=32 => size lhs=16 => size rhs=16 => be 4 kind <> be 4 0 =>
  node_query (seed ++ address layer tree kind kp ci cp ha ++ pad lhs ++ pad rhs).
proof.
  move=> hs hl hr hk.
  have hw := hash_pair_width seed (address layer tree kind kp ci cp ha) lhs rhs
    hs (raw_address_width _ _ _ _ _ _ _) hl hr.
  have ht := node_input_kind seed layer tree kind kp ci cp ha (pad lhs ++ pad rhs) hs.
  by rewrite /node_query hw /= -catA ht.
qed.

lemma node_query_compress seed a rows n :
  size seed=32 => size a=32 => rows_width n rows => n=13 \/ n=43 =>
  node_query (seed ++ a ++ flatten (map pad rows)).
proof.
  move=> hs ha hw hn.
  have hf := padded_flatten_width rows n hw.
  apply node_query_other_width; rewrite !size_cat hs ha hf; smt().
qed.

lemma node_query_wide_compress seed a rows n :
  size seed=32 => size a=32 => size rows=n =>
  all (fun (x : raw_input) => size x=32) rows => n=13 \/ n=43 =>
  node_query (seed ++ a ++ flatten rows).
proof.
  move=> hs ha hn hw hr.
  have hf := wide_flatten_width rows n hn hw.
  apply node_query_other_width; rewrite !size_cat hs ha hf; smt().
qed.

lemma node_query_merkle_kind : be 4 2 <> be 4 0.
proof. smt(be4_injective). qed.
lemma node_query_fors_kind : be 4 3 <> be 4 0.
proof. smt(be4_injective). qed.
