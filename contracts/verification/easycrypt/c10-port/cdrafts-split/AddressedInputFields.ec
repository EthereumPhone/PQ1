(* Equal public node prefixes determine all valid address fields. Short
   shuffle queries cannot form a distinct-input equal-prefix collision. *)
require import AllCore List IntDiv.
require import C10RawOracle C10Bytes RawKeygen RawSignature RawShuffle RawLayer.
require import ForsInputSeparation WotsInputSeparation AddressedNodeCollision.

op address_field_bytes (a : raw_input) =
  (take 4 a, take 8 (drop 4 a), take 4 (drop 12 a),
   take 4 (drop 16 a), take 4 (drop 20 a),
   take 4 (drop 24 a), take 4 (drop 28 a)).

lemma address_field_bytes_exact layer tree kind kp ci cp ha :
  address_field_bytes (address layer tree kind kp ci cp ha) =
    (be 4 layer, be 8 tree, be 4 kind, be 4 kp, be 4 ci, be 4 cp, be 4 ha).
proof.
  rewrite /address_field_bytes /address -!catA
    !take_cat !drop_cat !be_width //= ?take0 ?drop0 ?cats0
    ?take_size.
  rewrite !take_cat !be_width //= !take0 !cats0.
  have hw : size (be 4 ha)=4 by apply be_width.
  smt(take_oversize).
qed.

lemma address_fields_injective layer tree kind kp ci cp ha
    layer' tree' kind' kp' ci' cp' ha' :
  0<=layer<4294967296 => 0<=layer'<4294967296 =>
  0<=tree<2^64 => 0<=tree'<2^64 =>
  0<=kind<4294967296 => 0<=kind'<4294967296 =>
  0<=kp<4294967296 => 0<=kp'<4294967296 =>
  0<=ci<4294967296 => 0<=ci'<4294967296 =>
  0<=cp<4294967296 => 0<=cp'<4294967296 =>
  0<=ha<4294967296 => 0<=ha'<4294967296 =>
  address layer tree kind kp ci cp ha=address layer' tree' kind' kp' ci' cp' ha' =>
  layer=layer' /\ tree=tree' /\ kind=kind' /\ kp=kp' /\ ci=ci' /\ cp=cp' /\ ha=ha'.
proof.
  move=> hl hl' ht ht' hk hk' hp hp' hi hi' hc hc' hh hh' he.
  have hf : address_field_bytes (address layer tree kind kp ci cp ha)=
    address_field_bytes (address layer' tree' kind' kp' ci' cp' ha') by rewrite he.
  rewrite !address_field_bytes_exact in hf.
  have htree : tree=tree' by apply (be_injective 8); smt().
  smt(be4_injective).
qed.

lemma addressed_prefix_coordinates seed a payload seed' a' payload' :
  size seed=32 => size seed'=32 => size a=32 => size a'=32 =>
  same_node_address (seed ++ a ++ payload) (seed' ++ a' ++ payload') =>
  seed=seed' /\ a=a'.
proof.
  move=> hs hs' ha ha'; rewrite /same_node_address
    (node_prefix seed a payload hs ha) (node_prefix seed' a' payload' hs' ha').
  move=> he.
  have htake : take 32 (seed ++ a)=take 32 (seed' ++ a') by rewrite he.
  have hseed : seed=seed' by move: htake;
    rewrite !take_cat hs hs' /= !take0 !cats0.
  smt(catsI).
qed.

lemma short_same_address_is_same_input x y :
  size x<64 => same_node_address x y => x=y.
proof.
  move=> hx; rewrite /same_node_address.
  have tx : take 64 x=x by apply take_oversize; smt().
  rewrite tx => he.
  have hsize : size x=size (take 64 y) by rewrite he.
  have hy : size y<64 by move: hsize;
    rewrite size_take 1://; smt(size_ge0).
  have ty : take 64 y=y by apply take_oversize; smt().
  by rewrite he ty.
qed.

lemma shuffle_derive_input_short seed label :
  size seed=32 => size label<=7 => size (shuffle_tag ++ seed ++ label)<64.
proof. rewrite /shuffle_tag !size_cat /=; smt(). qed.

lemma shuffle_stream_input_short seed block :
  size seed=32 => size (fisher_tag ++ seed ++ be 4 block)<64.
proof. rewrite /fisher_tag !size_cat be_width //=; smt(). qed.

lemma layer_shuffle_label_short layer : size (layer_label layer)<=7.
proof. rewrite /layer_label; case (layer=0); smt(). qed.
