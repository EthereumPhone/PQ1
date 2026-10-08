(* Internal FORS and Merkle hashes do not consume accepted H_msg entries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawMerkle RawSignature RawWidths RawTreeWidths.
require import IndependentWidths ClientGuessCandidates AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes HmsgKeygenCount.

lemma hmsg_fors_tree_count c :
  hoare[RawFors(HmsgPreparation).tree : size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    size res.`1=16 /\ rows_width 11 res.`2].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\ rows_width 11 auth /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ rows_width 11 auth /\ size current=16 /\
      independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
    - wp; call (hmsg_nonmessage_width c); auto;
        smt(hash_pair_width raw_address_width node_width valid_stack_tail stack_first_width rows_put).
    wp; call (hmsg_nonmessage_width c); wp; call (hmsg_fors_private c).
    auto; rewrite /valid_stack /=; smt(hash_chain_width raw_address_width node_width).
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.

lemma hmsg_fors_sign_count c :
  hoare[RawFors(HmsgPreparation).sign : size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    size res.`1=16 /\ rows_width 11 res.`2].
proof.
  proc; call (hmsg_fors_tree_count c); wp; call (hmsg_fors_private c); auto; smt(node_width).
qed.
lemma hmsg_fors_root_count c :
  hoare[RawFors(HmsgPreparation).root : size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof. proc; call (hmsg_fors_tree_count c); auto. qed.

lemma hmsg_fors_recover_count c :
  hoare[RawFors(HmsgPreparation).recover : size seed=32 /\ size secret=16 /\ rows_width 11 auth /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ rows_width 11 auth /\ size current=16 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_nonmessage_width c); auto;
      smt(hash_pair_width raw_address_width node_width rows_nth_width).
  wp; call (hmsg_nonmessage_width c); auto; smt(hash_chain_width raw_address_width node_width).
qed.

lemma hmsg_merkle_build_count c :
  hoare[RawMerkle(HmsgPreparation).build : size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    rows_width 9 res.`1 /\ size res.`2=16].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\ rows_width 9 keep /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ rows_width 9 keep /\ size current=16 /\
      independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
    - wp; call (hmsg_nonmessage_width c); auto;
        smt(hash_pair_width raw_address_width node_width valid_stack_tail stack_first_width rows_put).
    wp; call (hmsg_leaf_count c); auto; rewrite /valid_stack /=; smt().
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.
lemma hmsg_merkle_recover_count c :
  hoare[RawMerkle(HmsgPreparation).recover : size seed=32 /\ size leaf=16 /\ rows_width 9 auth /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ rows_width 9 auth /\ size current=16 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_nonmessage_width c); auto;
      smt(hash_pair_width raw_address_width node_width rows_nth_width).
  auto.
qed.
