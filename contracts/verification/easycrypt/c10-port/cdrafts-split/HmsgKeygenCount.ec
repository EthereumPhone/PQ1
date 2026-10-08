(* Key generation consumes no accepted H_msg entries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import RawTreeWidths RawSignature IndependentWidths ClientGuessCandidates.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes.

lemma hmsg_leaf_count c :
  hoare [RawKeygen(HmsgPreparation).leaf :
    size seed=32 /\ independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; call (hmsg_nonmessage_width c); wp.
  while (size seed=32 /\ 0<=i<=43 /\ size elements=i /\ all (fun (x : raw_input) => size x=32) elements /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ size current=16 /\
      independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
    - wp; call (hmsg_nonmessage_width c); auto; smt(hash_chain_width raw_address_width node_width).
    wp; call (hmsg_wots_private c); auto; smt(node_width pad_node_width all_cat cats1 size_rcons).
  auto; smt(wide_flatten_width raw_address_width size_cat node_width).
qed.

lemma hmsg_keygen_root_count c :
  hoare [RawKeygen(HmsgPreparation).root :
    size seed=32 /\ independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ size current=16 /\
      independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
    - wp; call (hmsg_nonmessage_width c); auto;
        smt(hash_pair_width raw_address_width node_width valid_stack_tail stack_first_width).
    wp; call (hmsg_leaf_count c); auto; rewrite /valid_stack /=; smt().
  auto; rewrite /valid_stack /=; smt(valid_stack_head).
qed.
