require import AllCore List Distr DList DBool IidSelection.
lemma selected_iid :
  dmap (dlist dbool 2) (fun xs => map (nth false xs) [0;0])=dlist dbool 2.
proof.
  apply (iid_distinct_selection false dbool 2 [0;0] dbool_ll); by simplify.
qed.
