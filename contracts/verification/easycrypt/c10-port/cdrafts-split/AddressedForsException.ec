(* The special final FORS root shares the leaf-zero address. These predicates
   classify public node queries only; count/H_msg queries are excluded by the
   existing node domain. No honest-query budget is assumed here. *)
require import AllCore List IntDiv.
require import C10RawOracle RawKeygen RawSignature RawForsPathReplay.
require import ClientGuessCandidates NodeQueryDomain ForsInputSeparation.
require import AddressedInputFields.

op exceptional_fors_address (x : raw_input) =
  let fields=address_field_bytes (take 32 (drop 32 x)) in
    fields.`3=be 4 3 /\ fields.`4=be 4 12 /\ fields.`5=be 4 0 /\
    fields.`6=be 4 0 /\ fields.`7=be 4 0.
op exceptional_fors_query x = node_query x /\ exceptional_fors_address x.

lemma public_input_address_bytes (seed a payload : raw_input) :
  size seed=32 => size a=32 => take 32 (drop 32 (seed++a++payload))=a.
proof.
  move=> hs ha; by rewrite -catA drop_cat hs /= drop0 take_cat ha /= take0 cats0.
qed.

lemma exceptional_fors_address_fields seed layer tree kind kp ci cp ha payload :
  size seed=32 =>
  exceptional_fors_address (seed++address layer tree kind kp ci cp ha++payload) <=>
    be 4 kind=be 4 3 /\ be 4 kp=be 4 12 /\ be 4 ci=be 4 0 /\
    be 4 cp=be 4 0 /\ be 4 ha=be 4 0.
proof.
  move=> hs; rewrite /exceptional_fors_address
    (public_input_address_bytes seed (address layer tree kind kp ci cp ha) payload
      hs (raw_address_width _ _ _ _ _ _ _)) address_field_bytes_exact; smt().
qed.

lemma exceptional_fors_leaf_query seed ht tree index secret :
  size seed=32 => size secret=16 => 0<=tree<13 => 0<=index<2048 =>
  exceptional_fors_query (seed++address 0 ht 3 tree 0 0 index++pad secret) <=>
    tree=12 /\ index=0.
proof.
  move=> hs hv htr hi.
  have hn := node_query_chain seed (address 0 ht 3 tree 0 0 index) secret hs
    (raw_address_width _ _ _ _ _ _ _) hv.
  rewrite /exceptional_fors_query hn /= (exceptional_fors_address_fields _ _ _ _ _ _ _ _ _ hs).
  smt(be4_injective).
qed.

lemma exceptional_fors_parent_excluded seed ht tree level parent lval rval :
  size seed=32 => 1<=level<4294967296 =>
  !exceptional_fors_query (fors_pair seed ht tree level parent lval rval).
proof.
  move=> hs hl; apply/negP; rewrite /exceptional_fors_query /fors_pair.
  move=> [hn ha].
  have hf := exceptional_fors_address_fields seed 0 ht 3 tree 0 level parent
    (pad lval++pad rval) hs.
  have he : be 4 level=be 4 0 by move: ha; rewrite -catA; smt().
  smt(be4_injective).
qed.

lemma exceptional_fors_other_kind seed layer tree kind kp ci cp ha payload :
  size seed=32 => 0<=kind<4294967296 => kind<>3 =>
  !exceptional_fors_query (seed++address layer tree kind kp ci cp ha++payload).
proof.
  move=> hs hk hn; apply/negP; rewrite /exceptional_fors_query.
  move=> [hq ha0].
  have hf := exceptional_fors_address_fields seed layer tree kind kp ci cp ha payload hs.
  smt(be4_injective).
qed.

lemma exceptional_fors_non_node x : !node_query x => !exceptional_fors_query x.
proof. rewrite /exceptional_fors_query; smt(). qed.

lemma exceptional_fors_address_full_prefix x : exceptional_fors_address x => 64<=size x.
proof.
  rewrite /exceptional_fors_address /address_field_bytes /= => ha.
  have hh : take 4 (drop 28 (take 32 (drop 32 x)))=be 4 0 by smt().
  have hw : size (take 4 (drop 28 (take 32 (drop 32 x))))=4
    by rewrite hh be_width.
  have hdrop : 4<=size (drop 28 (take 32 (drop 32 x)))
    by move: hw; rewrite size_take 1://; smt().
  have htake : 32<=size (take 32 (drop 32 x))
    by move: hdrop; rewrite size_drop; smt().
  have hrest : 32<=size (drop 32 x)
    by move: htake; rewrite size_take 1://; smt().
  move: hrest; rewrite size_drop; smt().
qed.

lemma exceptional_fors_short_excluded x : size x<64 => !exceptional_fors_query x.
proof. rewrite /exceptional_fors_query; smt(exceptional_fors_address_full_prefix). qed.

lemma exceptional_fors_other_tree seed ht tree ci cp ha payload :
  size seed=32 => 0<=tree<12 =>
  !exceptional_fors_query (seed++address 0 ht 3 tree ci cp ha++payload).
proof.
  move=> hs htr; apply/negP; rewrite /exceptional_fors_query => hp.
  have hf := exceptional_fors_address_fields seed 0 ht 3 tree ci cp ha payload hs.
  smt(be4_injective).
qed.
