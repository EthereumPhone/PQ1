(* WOTS hashes preserve the accepted H_msg-entry count. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawShuffle RawSignature RawWidths.
require import IndependentWidths ClientGuessCandidates AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes.

lemma hmsg_wots_count c :
  hoare[RawWots(HmsgPreparation).count : size seed=32 /\ size message=16 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (res <> None => 0 <= (oget res).`1 < signing_budget)].
proof.
  proc; while (size seed=32 /\ size message=16 /\ 0<=i<=signing_budget /\
    (result <> None => 0 <= (oget result).`1 < signing_budget) /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_nonmessage_width c); auto; smt(hash_count_width raw_address_width).
  auto; smt().
qed.
lemma hmsg_wots_chain_count c :
  hoare[RawWots(HmsgPreparation).chain : size seed=32 /\ size current=16 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ size current=16 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_nonmessage_width c); auto; smt(hash_chain_width raw_address_width node_width).
  auto.
qed.
lemma hmsg_wots_sign_count c :
  hoare[RawWots(HmsgPreparation).sign : size seed=32 /\ size message=16 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (res <> None => rows_width 43 (oget res).`1 /\ 0 <= (oget res).`2 < signing_budget)].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (accepted <> None => 0 <= (oget accepted).`1 < signing_budget)).
  + call (hmsg_wots_count c); auto.
  sp 1; if; last by auto.
  wp; while (size seed=32 /\ rows_width 43 sigma /\ 0 <= (oget accepted).`1 < signing_budget /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_wots_chain_count c); call (hmsg_wots_private c); auto; smt(node_width rows_put).
  wp; call (hmsg_shuffle_permutation c); auto; smt(rows_zeros).
qed.
lemma hmsg_wots_recover_count c :
  hoare[RawWots(HmsgPreparation).recover : size seed=32 /\ size message=16 /\ rows_width 43 sigma /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; seq 1 : (size seed=32 /\ rows_width 43 sigma /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + call (hmsg_nonmessage_width c); auto; smt(hash_count_width raw_address_width).
  sp 1; if; last by auto; smt(size_nseq).
  wp; call (hmsg_nonmessage_width c); wp.
  while (size seed=32 /\ rows_width 43 sigma /\ 0<=i<=43 /\ size elements=i /\
    all (fun (x : raw_input) => size x=32) elements /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_wots_chain_count c); auto;
      smt(rows_nth_width pad_node_width all_cat cats1 size_rcons).
  auto; smt(wide_flatten_width raw_address_width size_cat node_width).
qed.
