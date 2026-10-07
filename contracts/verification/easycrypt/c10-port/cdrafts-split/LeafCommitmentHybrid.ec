(* One hidden node used at the padded suffix of public leaf commitments.
   derive(prefix) is a commitment oracle, NOT a private-key derivation oracle. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid.
require import RawKeygen NodeDistribution EncodedSlices.

op leaf_suffix_candidate (x : raw_input) = take 16 (drop (size x-32) x).

lemma padded_leaf_suffix prefix key : size key=16 =>
  leaf_suffix_candidate (prefix ++ pad key)=key.
proof.
  move=> hk; rewrite /leaf_suffix_candidate /pad !size_cat hk size_nseq /=.
  have h : size prefix+32-32=size prefix by smt().
  rewrite h drop_cat_le; first smt(size_ge0).
qed.

module LeafCommitmentReal = {
  var key : raw_input
  proc hash(x : raw_input) : digest = {
    var y; y <@ Shared.hash(x); return y;
  }
  proc derive(prefix : raw_input) : digest = {
    var y; y <@ Shared.hash(prefix ++ pad key); return y;
  }
}.
module LeafCommitmentHybrid = {
  var key : raw_input
  var bad : bool
  proc hash(x : raw_input) : digest = {
    var y;
    bad <- bad \/ leaf_suffix_candidate x=key;
    y <@ Independent.hash(x); return y;
  }
  proc derive = Independent.derive
}.

op leaf_commitment_tables key (physical raw commitments : (raw_input,digest) fmap) =
  (forall x, leaf_suffix_candidate x<>key => physical.[x]=raw.[x]) /\
  (forall prefix, physical.[prefix ++ pad key]=commitments.[prefix]).

lemma leaf_commitment_public_update key physical raw commitments x y :
  size key=16 => leaf_suffix_candidate x<>key =>
  leaf_commitment_tables key physical raw commitments =>
  leaf_commitment_tables key physical.[x<-y] raw.[x<-y] commitments.
proof.
  rewrite /leaf_commitment_tables => hk hx [hpub hpriv]; split.
  + move=> z hz; rewrite !get_setE; smt().
  move=> prefix; rewrite get_setE.
  have hn : prefix ++ pad key <> x by smt(padded_leaf_suffix).
  smt().
qed.
lemma leaf_commitment_private_update key physical raw commitments prefix y :
  size key=16 => leaf_commitment_tables key physical raw commitments =>
  leaf_commitment_tables key physical.[prefix ++ pad key<-y] raw commitments.[prefix<-y].
proof.
  rewrite /leaf_commitment_tables => hk [hpub hpriv]; split.
  + move=> x hx; rewrite get_setE; smt(padded_leaf_suffix).
  move=> p; rewrite !get_setE; smt(catIs).
qed.
lemma leaf_commitment_public_query :
  equiv [LeafCommitmentReal.hash ~ LeafCommitmentHybrid.hash :
    ={x} /\ LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\
    size LeafCommitmentHybrid.key{2}=16 /\ !LeafCommitmentHybrid.bad{2} /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !LeafCommitmentHybrid.bad{2} => ={res} /\
    LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\ size LeafCommitmentHybrid.key{2}=16 /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  proc; case (leaf_suffix_candidate x{2}=LeafCommitmentHybrid.key{2}).
  + wp; call{1} hash_ll; call{2} independent_hash_ll; auto; smt().
  inline *; sp 2 3; if.
  + auto; rewrite /leaf_commitment_tables; smt(domE).
  + auto; smt(leaf_commitment_public_update get_set_sameE).
  auto; rewrite /leaf_commitment_tables; smt().
qed.
lemma leaf_commitment_private_query :
  equiv [LeafCommitmentReal.derive ~ LeafCommitmentHybrid.derive :
    prefix{1}=tail{2} /\ LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\
    size LeafCommitmentHybrid.key{2}=16 /\ !LeafCommitmentHybrid.bad{2} /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !LeafCommitmentHybrid.bad{2} => ={res} /\
    LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\ size LeafCommitmentHybrid.key{2}=16 /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  proc; inline *; sp 2 0; if.
  + auto; rewrite /leaf_commitment_tables; smt(domE).
  + auto; smt(leaf_commitment_private_update get_set_sameE).
  auto; rewrite /leaf_commitment_tables; smt().
qed.
lemma leaf_commitment_real_derive_ll : islossless LeafCommitmentReal.derive.
proof. proc; call hash_ll; auto. qed.
lemma leaf_commitment_hybrid_hash_ll : islossless LeafCommitmentHybrid.hash.
proof. proc; call independent_hash_ll; auto. qed.

module type LeafCommitmentContext (O : PrefixOracle) = {
  proc run() : raw_input list { O.hash, O.derive }
}.
lemma adaptive_leaf_commitment
  (A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) :
  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless A(O).run) =>
  equiv [A(LeafCommitmentReal).run ~ A(LeafCommitmentHybrid).run :
    ={glob A} /\ LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\
    size LeafCommitmentHybrid.key{2}=16 /\ !LeafCommitmentHybrid.bad{2} /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !LeafCommitmentHybrid.bad{2} => ={res,glob A} /\
    LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\ size LeafCommitmentHybrid.key{2}=16 /\
    leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  move=> hll.
  proc (LeafCommitmentHybrid.bad)
    (LeafCommitmentReal.key{1}=LeafCommitmentHybrid.key{2} /\ size LeafCommitmentHybrid.key{2}=16 /\
      leaf_commitment_tables LeafCommitmentHybrid.key{2} Shared.history{1}
        Independent.rawhistory{2} Independent.secrethistory{2}) true.
  + smt().
  + smt().
  + exact hll.
  + conseq leaf_commitment_public_query; smt().
  + move=> &2 _; proc; call hash_ll; auto.
  + move=> &1; proc; call independent_hash_ll; auto; smt().
  + conseq leaf_commitment_private_query; smt().
  + move=> &2 _; exact leaf_commitment_real_derive_ll.
  + move=> &1; proc; if; auto; smt(full_digest_ll).
qed.
